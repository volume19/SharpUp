//! ModifiableServiceBinaries check
//!
//! Checks for Windows service binaries that are modifiable by the current user

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::check_modifiable_access;
use crate::utils::registry::{get_reg_subkeys, get_reg_value, RegistryHive};
use regex::Regex;

const SERVICES_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services";

pub struct ModifiableServiceBinaries;

impl VulnerabilityCheck for ModifiableServiceBinaries {
    fn name(&self) -> &str {
        "Modifiable Service Binaries"
    }

    fn description(&self) -> &str {
        "Checks for Windows service binaries that are modifiable"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Regex to extract executable path from ImagePath
        let exe_regex = Regex::new(r#"(?i)([a-z]:\\.+?\.exe)"#)
            .map_err(|e| CheckError::Other(format!("Regex error: {}", e)))?;

        // Enumerate all services
        let service_names = match get_reg_subkeys(RegistryHive::HKLM, SERVICES_REG_PATH) {
            Ok(names) => names,
            Err(_) => {
                result.add_detail("Could not enumerate services from registry");
                return Ok(result);
            }
        };

        for service_name in service_names.iter().take(200) {
            // Check more services for binaries
            let service_path = format!("{}\\{}", SERVICES_REG_PATH, service_name);

            // Try to get ImagePath value
            let image_path = match get_reg_value(RegistryHive::HKLM, &service_path, "ImagePath") {
                Ok(path) => path,
                Err(_) => continue,
            };

            // Extract the executable path
            if let Some(caps) = exe_regex.captures(&image_path) {
                if let Some(exe_match) = caps.get(1) {
                    let exe_path = exe_match.as_str();

                    // Check if the binary is modifiable
                    if let Ok(true) = check_modifiable_access(exe_path) {
                        result.add_finding(format!(
                            "Service: {} - Modifiable Binary: {}",
                            service_name, exe_path
                        ));
                    }
                }
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No modifiable service binaries found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = ModifiableServiceBinaries;
        assert_eq!(check.name(), "Modifiable Service Binaries");
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = ModifiableServiceBinaries;
        let result = check.check();
        assert!(result.is_ok());
    }
}
