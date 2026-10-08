mod analysis;
mod collectors;
mod model;
mod storage;

use std::env;
use std::process::ExitCode;

#[cfg(windows)]
use crate::collectors::Collector;
#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[cfg(windows)]
use std::time::Duration;

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
}

#[cfg(windows)]
fn run_watch(pid: u32) -> Result<(), String> {
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

    for event in initial_events {
        active.insert(
            event.process.pid,
            ActiveProcess {
                name: event.process.executable.clone(),
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
    println!("Watching process starts and exits. Press Ctrl+C to stop.");

    let mut stop_reason = "stopped by user";
    let mut pending_events = queued_events.into_iter();

    'watch: loop {
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
                let timestamp_ms = collectors::windows_process::WindowsProcessCollector::now_ms();

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

    let ended_at_ms = collectors::windows_process::WindowsProcessCollector::now_ms();
    let final_passport = passport.finish(&run_id, ended_at_ms, &application);
    storage::finish_run(&mut connection, &run_id, ended_at_ms, &final_passport)
        .map_err(|error| error.to_string())?;

    println!();
    println!("Watch finished: {stop_reason}");
    println!("  Events saved:   {sequence}");
    println!("  Active at stop: {}", active.len());
    println!("  Run ID:         {run_id}");
    println!("  Passport ID:    {}", final_passport.passport_id);

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
            println!("  Network:         disabled by default");
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
