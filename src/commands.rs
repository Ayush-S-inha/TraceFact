use crate::{analysis, storage};
use std::process::ExitCode;

pub(super) fn handle_baseline(args: &[String]) -> ExitCode {
    match args {
        [action, name, run_id] if action == "save" => {
            match run_baseline_save(name.as_str(), run_id.as_str()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("TraceFact could not save baseline: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [action] if action == "list" => match run_baseline_list() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("TraceFact could not list baselines: {error}");
                ExitCode::FAILURE
            }
        },
        [action, name] if action == "inspect" => match run_baseline_inspect(name.as_str()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("TraceFact could not inspect baseline: {error}");
                ExitCode::FAILURE
            }
        },
        [action, name, path] if action == "export" => {
            match run_baseline_export(name.as_str(), path.as_str()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("TraceFact could not export baseline: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("Usage: tracefact baseline <save|list|inspect|export> ...");
            ExitCode::FAILURE
        }
    }
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
    let baseline = analysis::baseline_from_run(&run, name, super::current_unix_ms()?)?;
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
        "The baseline stays local. Names are unique, case-insensitive, and are never overwritten."
    );
    println!("Review coverage limits before treating it as an expected-behavior reference.");
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
                "Could not create baseline export at {}. Existing files are left untouched: {error}",
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
    println!("Review the file before sharing it. The scope and Passport may contain process IDs, process names, and network endpoints.");
    Ok(())
}
