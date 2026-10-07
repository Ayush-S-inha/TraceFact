mod analysis;
mod collectors;
mod model;
mod storage;

use std::env;
use std::process::ExitCode;

#[cfg(windows)]
use crate::collectors::Collector;

fn print_help() {
    println!("TraceFact 0.1.0");
    println!();
    println!("Usage:");
    println!("  tracefact doctor");
    println!("  tracefact demo");
    println!("  tracefact process <pid>");
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
