//! ModifiableScheduledTaskFile check
//!
//! Checks for scheduled tasks with modifiable binaries

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::{check_modifiable_access, find_files};
use regex::Regex;
use std::fs;

const TASK_PATHS: &[&str] = &[
    "C:\\Windows\\System32\\Tasks",
    "C:\\Windows\\Tasks",
];

pub struct ModifiableScheduledTask;

impl VulnerabilityCheck for ModifiableScheduledTask {
    fn name(&self) -> &str {
        "Modifiable Scheduled Task Files"
    }

    fn description(&self) -> &str {
        "Checks for scheduled tasks with modifiable binaries"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Regex to extract executable paths from XML
        let exe_regex = Regex::new(r#"(?i)<Command>([^<]+\.exe)</Command>"#)
            .map_err(|e| CheckError::Other(format!("Regex error: {}", e)))?;

        let path_regex = Regex::new(r#"(?i)([a-z]:\\.+?\.exe)"#)
            .map_err(|e| CheckError::Other(format!("Regex error: {}", e)))?;

        for task_dir in TASK_PATHS {
            // Find all task files (XML format in System32\Tasks, .job in Tasks)
            let task_files = find_files(task_dir, &["*"]);

            for task_file in task_files.iter().take(50) {
                // Limit for performance
                // Try to read task file
                if let Ok(content) = fs::read_to_string(task_file) {
                    // Look for Command elements in task XML
                    for cap in exe_regex.captures_iter(&content) {
                        if let Some(command) = cap.get(1) {
                            let cmd_str = command.as_str();

                            // Extract the executable path
                            if let Some(path_cap) = path_regex.captures(cmd_str) {
                                if let Some(exe_path) = path_cap.get(1) {
                                    let exe = exe_path.as_str();

                                    // Check if modifiable
                                    if let Ok(true) = check_modifiable_access(exe) {
                                        result.add_finding(format!(
                                            "Task: {} - Modifiable Binary: {}",
                                            task_file.replace(task_dir, ""),
                                            exe
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No modifiable scheduled task binaries found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = ModifiableScheduledTask;
        assert_eq!(check.name(), "Modifiable Scheduled Task Files");
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = ModifiableScheduledTask;
        let result = check.check();
        assert!(result.is_ok());
    }
}
