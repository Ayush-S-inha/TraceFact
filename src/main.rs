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
    flow_targets: &mut HashMap<NetworkFlowKey, TrackedNetworkFlow>,
    connection: &mut rusqlite::Connection,
    passport: &mut analysis::PassportAccumulator,
    sequence: &mut u64,
) -> Result<bool, String> {
    use collectors::windows_network::{endpoint, NetworkOperation};

    const FLOW_CACHE_LIMIT: usize = 8192;
    const NEGATIVE_PID_CACHE_TTL: Duration = Duration::from_secs(2);

    let now = Instant::now();
    ignored_pids_until.retain(|_, expires_at| *expires_at > now);

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
            return Ok(false);
        }

        let member =
            collectors::windows_process::identify_process_in_tree(root_pid, observation.process_id)
                .map_err(|error| error.to_string())?;

        let Some(member) = member else {
            if ignored_pids_until.len() < 4096 {
                ignored_pids_until.insert(observation.process_id, now + NEGATIVE_PID_CACHE_TTL);
            }
            return Ok(false);
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

    *sequence = (*sequence).wrapping_add(1);
    let relationship = if observation.process_id == root_pid {
        "root"
    } else {
        "child"
    };
    let runtime_event = model::RuntimeEvent {
        id: format!("{run_id}-event-{sequence}"),
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

    Ok(true)
}

#[cfg(windows)]
fn drain_network_queue(
    receiver: &Receiver<collectors::windows_network::NetworkWatchMessage>,
    disconnected_is_error: bool,
    root_pid: u32,
    run_id: &str,
    active: &BTreeMap<u32, ActiveProcess>,
    ignored_pids_until: &mut HashMap<u32, Instant>,
    flow_targets: &mut HashMap<NetworkFlowKey, TrackedNetworkFlow>,
    connection: &mut rusqlite::Connection,
    passport: &mut analysis::PassportAccumulator,
    sequence: &mut u64,
    network_events_saved: &mut u64,
    network_events_filtered: &mut u64,
) -> Result<Option<String>, String> {
    use collectors::windows_network::NetworkWatchMessage;
    use std::sync::mpsc::TryRecvError;

    let mut first_error = None;
    loop {
        match receiver.try_recv() {
            Ok(NetworkWatchMessage::Event(observation)) => {
                if persist_network_observation(
                    observation,
                    root_pid,
                    run_id,
                    active,
                    ignored_pids_until,
                    flow_targets,
                    connection,
                    passport,
                    sequence,
                )? {
                    *network_events_saved = (*network_events_saved).wrapping_add(1);
                } else {
                    *network_events_filtered = (*network_events_filtered).wrapping_add(1);
                }
            }
            Ok(NetworkWatchMessage::Error(message)) => {
                if first_error.is_none() {
                    first_error = Some(message);
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

    let (mut connection, database_path) =
        storage::open_default().map_err(|error| error.to_string())?;
    let watcher = WindowsProcessEventWatcher::start();
    let receiver = watcher.receiver();

    let queued_events =
        wait_for_watchers(receiver, Duration::from_secs(10)).map_err(|error| error.to_string())?;

    let mut network_watcher =
        WindowsNetworkEventWatcher::start().map_err(|error| error.to_string())?;

    let initial_events = snapshot_process_tree(pid, &run_id).map_err(|error| error.to_string())?;
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
    storage::begin_run(&mut connection, &initial_snapshot, &initial_passport)
        .map_err(|error| error.to_string())?;

    let mut active = BTreeMap::<u32, ActiveProcess>::new();
    let mut passport = analysis::PassportAccumulator::default();
    let mut sequence = 0_u64;
    let mut network_events_saved = 0_u64;
    let mut network_events_filtered = 0_u64;
    let mut ignored_pids_until = HashMap::<u32, Instant>::new();
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
        storage::append_event(&mut connection, &run_id, &event)
            .map_err(|error| error.to_string())?;
        sequence = sequence.wrapping_add(1);
    }

    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop_requested);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    })
    .map_err(|error| format!("Could not install Ctrl+C handler: {error}"))?;

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

    let mut stop_reason = "stopped by user";
    let mut network_error = None;

    {
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
                &mut flow_targets,
                &mut connection,
                &mut passport,
                &mut sequence,
                &mut network_events_saved,
                &mut network_events_filtered,
            )? {
                network_error = Some(message);
                stop_reason = "network observer stopped";
                break 'watch;
            }

            let incoming = if let Some(event) = pending_events.next() {
                Some(event)
            } else if stop_requested.load(Ordering::SeqCst) {
                None
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

                    sequence = sequence.wrapping_add(1);
                    let runtime_event = build_process_lifecycle_event(
                        &run_id,
                        sequence,
                        pid,
                        timestamp_ms,
                        &event,
                        depth,
                    );

                    active.insert(
                        event.process_id,
                        ActiveProcess {
                            name: event.process_name.clone(),
                            depth,
                            parent_pid: Some(event.parent_process_id).filter(|parent| *parent != 0),
                        },
                    );
                    passport.observe(&runtime_event);
                    storage::append_event(&mut connection, &run_id, &runtime_event)
                        .map_err(|error| error.to_string())?;

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

                    sequence = sequence.wrapping_add(1);
                    let relationship = if event.process_id == pid {
                        "root"
                    } else {
                        "child"
                    };
                    let runtime_event = build_process_exit_event(
                        &run_id,
                        sequence,
                        pid,
                        collectors::windows_process::WindowsProcessCollector::now_ms(),
                        &event,
                        previous.depth,
                        relationship,
                    );

                    active.remove(&event.process_id);
                    passport.observe(&runtime_event);
                    storage::append_event(&mut connection, &run_id, &runtime_event)
                        .map_err(|error| error.to_string())?;

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
    }

    if let Err(error) = network_watcher.stop() {
        if network_error.is_none() {
            network_error = Some(error.to_string());
        }
    }

    if let Some(message) = drain_network_queue(
        network_watcher.receiver(),
        false,
        pid,
        &run_id,
        &active,
        &mut ignored_pids_until,
        &mut flow_targets,
        &mut connection,
        &mut passport,
        &mut sequence,
        &mut network_events_saved,
        &mut network_events_filtered,
    )? {
        if network_error.is_none() {
            network_error = Some(message);
        }
    }

    let ended_at_ms = collectors::windows_process::WindowsProcessCollector::now_ms();
    let final_passport = passport.finish(&run_id, ended_at_ms, &application);
    storage::finish_run(&mut connection, &run_id, ended_at_ms, &final_passport)
        .map_err(|error| error.to_string())?;

    let network_diagnostics = network_watcher.diagnostics();

    println!();
    println!("Watch finished: {stop_reason}");
    println!("  Events saved:         {sequence}");
    println!("  Network events saved: {network_events_saved}");
    println!("  Network events filtered: {network_events_filtered}");
    println!(
        "  Network queue drops:  {}",
        network_watcher.dropped_events()
    );
    println!("  Active at stop:       {}", active.len());

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

    println!("  RUN ID                 APPLICATION              EVENTS   STARTED AT");
    println!("  --------------------------------------------------------------------------");

    for run in runs {
        println!(
            "  {:<22} {:<24} {:>6}   {}",
            run.run_id, run.application, run.event_count, run.started_at_ms
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
