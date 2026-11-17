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

pub(super) fn handle_inspect(args: &[String]) -> ExitCode {
    match args {
        [run_id] => match run_inspect(run_id) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("TraceFact could not inspect run {run_id}: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("Usage: tracefact inspect <run_id|latest>");
            ExitCode::FAILURE
        }
    }
}

pub(super) fn handle_export(args: &[String]) -> ExitCode {
    match args {
        [run_id, export_path] => match run_export(run_id, export_path) {
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
    }
}

pub(super) fn handle_compare(args: &[String]) -> ExitCode {
    match args {
        [baseline_name, run_id] => match run_compare(baseline_name, run_id, None) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("TraceFact could not compare behavior: {error}");
                ExitCode::FAILURE
            }
        },
        [baseline_name, run_id, report_path] => {
            match run_compare(
                baseline_name.as_str(),
                run_id.as_str(),
                Some(report_path.as_str()),
            ) {
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
    }
}

pub(super) fn handle_history(args: &[String]) -> ExitCode {
    match args {
        [] => match run_history(20) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("TraceFact could not read history: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("Usage: tracefact history");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod stored_command_tests {
    use super::{handle_compare, handle_export, handle_history, handle_inspect};
    use std::process::ExitCode;

    #[test]
    fn stored_commands_reject_invalid_argument_counts() {
        let extra = ["unexpected".to_string()];
        let too_many = [
            "baseline".to_string(),
            "run-id".to_string(),
            "report.json".to_string(),
            "unexpected".to_string(),
        ];

        assert_eq!(handle_inspect(&[]), ExitCode::FAILURE);
        assert_eq!(handle_inspect(&too_many), ExitCode::FAILURE);
        assert_eq!(handle_export(&[]), ExitCode::FAILURE);
        assert_eq!(handle_export(&extra), ExitCode::FAILURE);
        assert_eq!(handle_compare(&[]), ExitCode::FAILURE);
        assert_eq!(handle_compare(&extra), ExitCode::FAILURE);
        assert_eq!(handle_compare(&too_many), ExitCode::FAILURE);
        assert_eq!(handle_history(&extra), ExitCode::FAILURE);
    }
}

fn display_sensitivity(sensitivity: &str) -> &str {
    match sensitivity {
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

fn run_export(run_id: &str, export_path: &str) -> Result<(), String> {
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
    let path = std::path::Path::new(export_path);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "Could not create export at {}. Existing files are left untouched: {error}",
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
    println!("Check the exported file before sharing it. Event metadata may include process IDs,");
    println!("executable names, and network endpoints. Application payloads are not collected.");
    Ok(())
}

fn run_compare(baseline_name: &str, run_id: &str, report_path: Option<&str>) -> Result<(), String> {
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
            "Baseline source run '{}' is not completed. Comparison stopped.",
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
        super::current_unix_ms()?,
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
            "No findings were generated because the baseline and current observation scopes differ."
        );
    } else if report.compared_categories.is_empty() {
        println!("No findings were generated because no category had enough stored provenance.");
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
    println!("Differences reflect stored observations. They do not establish malicious behavior.");

    if let Some(report_path) = report_path {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|error| format!("Could not serialize comparison report: {error}"))?;
        let path = std::path::Path::new(report_path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!(
                "Could not create comparison report at {}. Existing files are left untouched: {error}",
                path.display()
            ))?;
        if let Err(error) = file.write_all(&json).and_then(|_| file.write_all(b"\n")) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(format!("Could not write comparison report: {error}"));
        }
        println!("Comparison report exported to: {}", path.display());
        println!(
            "Review the report before sharing it. It contains local process and endpoint metadata."
        );
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
