pub(super) fn print_help() {
    println!("TraceFact 0.1.0");
    println!();
    println!("Usage:");
    println!("  tracefact doctor");
    println!("  tracefact demo");
    println!("  tracefact process <pid>");
    println!("  tracefact watch <pid> [--duration <seconds>]");
    println!("  tracefact watch-files <directory> [duration_seconds]");
    println!("    Quote directory paths that contain spaces.");
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
        "The process command records the selected Windows process tree and its loaded modules, creates a Runtime Passport, and saves both locally."
    );
}

pub(super) fn parse_pid(input: &str) -> Result<u32, String> {
    let pid = input
        .parse::<u32>()
        .map_err(|_| "PID must be a positive 32-bit integer.".to_string())?;
    if pid == 0 {
        return Err("PID must be greater than zero.".to_string());
    }
    Ok(pid)
}

pub(super) fn parse_duration(input: &str) -> Result<u64, String> {
    let seconds = input
        .parse::<u64>()
        .map_err(|_| "Duration must be a positive number of seconds.".to_string())?;
    if seconds == 0 {
        return Err("Duration must be greater than zero seconds.".to_string());
    }
    Ok(seconds)
}
