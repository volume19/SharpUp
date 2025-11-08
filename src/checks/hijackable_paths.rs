//! HijackablePaths check
//!
//! Checks for writable directories in the system %PATH% environment variable

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::check_modifiable_access;
use crate::utils::registry::{get_reg_value, RegistryHive};

const REG_PATH: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const REG_NAME: &str = "Path";

pub struct HijackablePaths;

impl VulnerabilityCheck for HijackablePaths {
    fn name(&self) -> &str {
        "Modifiable Folders in %PATH%"
    }

    fn description(&self) -> &str {
        "Checks for writable directories in system PATH environment variable"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Get PATH from registry
        let path = match get_reg_value(RegistryHive::HKLM, REG_PATH, REG_NAME) {
            Ok(p) => p,
            Err(_) => {
                result.add_detail("Could not read PATH from registry");
                return Ok(result);
            }
        };

        if path.is_empty() {
            result.add_detail("PATH is empty");
            return Ok(result);
        }

        // Split PATH by semicolon
        let folders: Vec<&str> = path.split(';').filter(|s| !s.is_empty()).collect();

        for folder in folders {
            // Check if folder is modifiable
            if let Ok(true) = check_modifiable_access(folder) {
                result.add_finding(folder.to_string());
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No modifiable folders in PATH");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = HijackablePaths;
        assert_eq!(check.name(), "Modifiable Folders in %PATH%");
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = HijackablePaths;
        let result = check.check();
        assert!(result.is_ok());
    }
}
