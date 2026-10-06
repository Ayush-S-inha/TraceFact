mod analysis;
mod collectors;
mod model;
mod storage;

use std::env;

fn print_help() {
    println!("TraceFact 0.1.0");
    println!();
    println!("Usage:");
    println!("  tracefact doctor");
    println!("  tracefact demo");
    println!("  tracefact help");
    println!();
    println!(
        "0.1 is the architecture foundation. The next step is the first real runtime collector."
    );
}

fn main() {
    match env::args().nth(1).as_deref() {
        Some("doctor") => {
            println!("TraceFact doctor");
            println!("  Core:            ready");
            println!("  Storage design:  SQLite");
            println!("  Network:         disabled by default");
            println!("  Telemetry:       disabled");
            println!("  AI:              optional / not required");
        }
        Some("demo") => {
            let passport = collectors::demo::build_demo_passport();
            println!("{}", serde_json::to_string_pretty(&passport).unwrap());
        }
        _ => print_help(),
    }
}
