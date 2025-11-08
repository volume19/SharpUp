//! Unattended installation files check
//!
//! Checks for the presence of unattended installation files which may
//! contain credentials or sensitive configuration data.

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use std::path::Path;

/// Check for unattended install files
pub struct UnattendedInstallFiles;

impl VulnerabilityCheck for UnattendedInstallFiles {
    fn name(&self) -> &str {
        "Unattended Install Files"
    }

    fn description(&self) -> &str {
        "Checks for unattended installation files that may contain credentials"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Get Windows directory
        let windir = std::env::var("windir").unwrap_or_else(|_| "C:\\Windows".to_string());

        // Common locations for unattended install files
        let search_locations = vec![
            format!("{}\\sysprep\\sysprep.xml", windir),
            format!("{}\\sysprep\\sysprep.inf", windir),
            format!("{}\\sysprep.inf", windir),
            format!("{}\\Panther\\Unattended.xml", windir),
            format!("{}\\Panther\\Unattend.xml", windir),
            format!("{}\\Panther\\Unattend\\Unattended.xml", windir),
            format!("{}\\Panther\\Unattend\\Unattend.xml", windir),
            format!("{}\\System32\\Sysprep\\unattend.xml", windir),
            format!("{}\\System32\\Sysprep\\Panther\\unattend.xml", windir),
            "C:\\unattend.txt".to_string(),
            "C:\\unattend.inf".to_string(),
        ];

        let mut found_files = Vec::new();

        for location in &search_locations {
            let path = Path::new(location);
            if path.exists() {
                found_files.push(location.clone());
            }
        }

        if !found_files.is_empty() {
            for file in &found_files {
                result.add_finding(format!("Found: {}", file));
            }
        } else {
            result.add_detail("No unattended install files found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = UnattendedInstallFiles;
        assert_eq!(check.name(), "Unattended Install Files");
    }

    #[test]
    fn test_check_execution() {
        let check = UnattendedInstallFiles;
        let result = check.check();
        assert!(result.is_ok(), "Check should execute successfully");
    }
}
