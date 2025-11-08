//! SharpUp CLI entry point

use anyhow::Result;
use clap::Parser;
use sharpup::checks::VulnerabilityCheck;
use sharpup::CheckResult;
use std::time::Instant;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

// Import all checks
use sharpup::checks::{
    always_install_elevated::AlwaysInstallElevated, registry_autologons::RegistryAutoLogons,
    token_privileges::TokenPrivileges, unattended_install_files::UnattendedInstallFiles,
};

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

/// Registry of all available checks
fn get_all_checks() -> Vec<(&'static str, Box<dyn VulnerabilityCheck>)> {
    vec![
        (
            "AlwaysInstallElevated",
            Box::new(AlwaysInstallElevated) as Box<dyn VulnerabilityCheck>,
        ),
        ("TokenPrivileges", Box::new(TokenPrivileges)),
        ("RegistryAutoLogons", Box::new(RegistryAutoLogons)),
        (
            "UnattendedInstallFiles",
            Box::new(UnattendedInstallFiles),
        ),
    ]
}

/// Filter checks based on user-provided names
fn filter_checks(
    all_checks: Vec<(&'static str, Box<dyn VulnerabilityCheck>)>,
    requested: &[String],
) -> Vec<Box<dyn VulnerabilityCheck>> {
    if requested.is_empty() {
        return all_checks.into_iter().map(|(_, check)| check).collect();
    }

    let requested_lower: Vec<String> = requested.iter().map(|s| s.to_lowercase()).collect();

    all_checks
        .into_iter()
        .filter(|(name, _)| requested_lower.contains(&name.to_lowercase()))
        .map(|(_, check)| check)
        .collect()
}

/// Run privilege escalation checks
fn run_privesc_checks(checks: Vec<Box<dyn VulnerabilityCheck>>, audit_mode: bool) -> Result<()> {
    use sharpup::utils::{is_high_integrity, is_local_admin};

    let is_high = is_high_integrity().unwrap_or(false);
    let is_admin = is_local_admin().unwrap_or(false);
    let mut should_quit = false;

    if is_high {
        println!("\r\n[*] Already in high integrity, no need to privesc!");
        should_quit = true;
    } else if !is_high && is_admin {
        println!("\r\n[*] In medium integrity but user is a local administrator- UAC can be bypassed.");
        should_quit = true;
    }

    if should_quit && !audit_mode {
        println!(
            "\r\n[*] Quitting now, re-run with \"--audit\" argument to run checks anyway (audit mode)."
        );
        return Ok(());
    } else if should_quit {
        println!(
            "\r\n[*] Audit mode: running {} check(s).",
            checks.len()
        );
        if is_high {
            println!("[*] Note: Running audit mode in high integrity will yield a large number of false positives.");
        }
    }

    // Run checks in parallel
    let results: Vec<CheckResult> = checks
        .into_iter()
        .filter_map(|check| {
            match check.check() {
                Ok(result) => Some(result),
                Err(e) => {
                    warn!("Check '{}' failed: {}", check.name(), e);
                    None
                }
            }
        })
        .collect();

    // Filter to vulnerable checks only
    let vulnerable: Vec<&CheckResult> = results
        .iter()
        .filter(|r| r.is_vulnerable)
        .collect();

    if vulnerable.is_empty() {
        println!("\r\n[-] Not vulnerable to any of the {} checked modules.", results.len());
    } else {
        for result in vulnerable {
            println!("\r\n=== {} ===", result.name);
            for detail in &result.details {
                println!("\t{}", detail);
            }
            println!();
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::WARN // Only show warnings and errors by default
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let start_time = Instant::now();

    println!("\r\n=== SharpUp: Running Privilege Escalation Checks ===");

    let all_checks = get_all_checks();
    let checks_to_run = filter_checks(all_checks, &args.checks);

    if checks_to_run.is_empty() {
        println!("\r\n[!] No matching checks found.");
        println!("\r\nAvailable checks:");
        for (name, check) in get_all_checks() {
            println!("  - {}: {}", name, check.description());
        }
        return Ok(());
    }

    info!("Running {} checks", checks_to_run.len());

    run_privesc_checks(checks_to_run, args.audit)?;

    let elapsed = start_time.elapsed();
    println!(
        "\r\n\r\n[*] Completed Privesc Checks in {:.2} seconds\r\n",
        elapsed.as_secs_f64()
    );

    Ok(())
}
