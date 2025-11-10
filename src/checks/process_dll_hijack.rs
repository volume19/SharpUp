//! ProcessDLLHijack check
//!
//! Checks for potential DLL hijacking opportunities

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::check_modifiable_access;
use std::env;
use std::path::PathBuf;

pub struct ProcessDllHijack;

impl VulnerabilityCheck for ProcessDllHijack {
    fn name(&self) -> &str {
        "Process DLL Hijack"
    }

    fn description(&self) -> &str {
        "Checks for potential DLL hijacking opportunities in system paths"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Get the PATH environment variable
        let path_var = match env::var("PATH") {
            Ok(p) => p,
            Err(_) => {
                result.add_detail("Could not read PATH environment variable");
                return Ok(result);
            }
        };

        let path_dirs: Vec<&str> = path_var.split(';').filter(|s| !s.is_empty()).collect();

        // Check each directory in PATH
        for dir in path_dirs {
            // Skip system directories
            let dir_lower = dir.to_lowercase();
            if dir_lower.contains("system32") || dir_lower.contains("\\windows\\") {
                continue;
            }

            // Check if the directory is writable
            if let Ok(true) = check_modifiable_access(dir) {
                // This directory is in PATH and writable - potential for DLL hijacking
                result.add_finding(format!(
                    "Writable directory in PATH: {} (could place DLLs here for hijacking)",
                    dir
                ));
            }
        }

        // Also check current directory (always searched first for DLL loading)
        if let Ok(current_dir) = env::current_dir() {
            if let Ok(true) = check_modifiable_access(current_dir.to_str().unwrap_or("")) {
                result.add_finding(format!(
                    "Current directory is writable: {} (DLL search order vulnerability)",
                    current_dir.display()
                ));
            }
        }

        // Check common application directories for missing DLLs
        let program_files = [
            env::var("ProgramFiles").unwrap_or_default(),
            env::var("ProgramFiles(x86)").unwrap_or_default(),
        ];

        for base_dir in &program_files {
            if base_dir.is_empty() {
                continue;
            }

            let base_path = PathBuf::from(base_dir);
            if !base_path.exists() {
                continue;
            }

            // Check if any directories under Program Files are writable
            // (simplified check - only checking the base directory)
            if let Ok(true) = check_modifiable_access(base_dir) {
                result.add_finding(format!(
                    "Program Files directory is writable: {} (high-value DLL hijack target)",
                    base_dir
                ));
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No obvious DLL hijacking opportunities found in PATH");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = ProcessDllHijack;
        assert_eq!(check.name(), "Process DLL Hijack");
    }

    #[test]
    fn test_check_execution() {
        let check = ProcessDllHijack;
        let result = check.check();
        assert!(result.is_ok());
    }
}
