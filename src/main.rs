//! SharpUp CLI entry point

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "SharpUp")]
#[command(about = "Windows Privilege Escalation Enumeration Tool", long_about = None)]
struct Args {
    /// Enable audit mode (run checks even if already admin)
    #[arg(long)]
    audit: bool,

    /// Specific checks to run (if empty, runs all)
    checks: Vec<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("SharpUp: Running Privilege Escalation Checks");

    // TODO: Implement check execution
    println!("\n=== SharpUp: Running Privilege Escalation Checks ===");

    if args.audit {
        println!("[*] Audit mode enabled");
    }

    if args.checks.is_empty() {
        println!("[*] No checks implemented yet");
    } else {
        println!("[*] Requested checks: {:?}", args.checks);
    }

    println!("\n[*] Completed (foundation only - checks not yet implemented)");

    Ok(())
}
