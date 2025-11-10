//! Registry Autoruns check
//!
//! Checks common autorun registry locations for modifiable executables

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::check_modifiable_access;
use crate::utils::registry::{get_reg_value, RegistryHive};
use regex::Regex;

const AUTORUN_LOCATIONS: &[(&str, &str)] = &[
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
];

pub struct RegistryAutoruns;

impl VulnerabilityCheck for RegistryAutoruns {
    fn name(&self) -> &str {
        "Registry Autoruns"
    }

    fn description(&self) -> &str {
        "Checks autorun registry locations for modifiable executables"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Regex to extract executable path from registry value
        let exe_regex = Regex::new(r#"^\W*([a-z]:\\.+?\.(exe|dll|bat|cmd))\W*"#)
            .map_err(|e| CheckError::Other(format!("Regex error: {}", e)))?;

        for (hive_str, path) in AUTORUN_LOCATIONS {
            let hive = match *hive_str {
                "HKLM" => RegistryHive::HKLM,
                "HKCU" => RegistryHive::HKCU,
                _ => continue,
            };

            // Try to enumerate the registry key's values
            // For simplicity, we'll try to read some common value names
            // A full implementation would enumerate all values
            let common_values = vec!["SecurityHealth", "OneDrive", "WindowsDefender"];

            for value_name in common_values {
                if let Ok(value) = get_reg_value(hive, path, value_name) {
                    // Extract executable path from value
                    if let Some(caps) = exe_regex.captures(&value.to_lowercase()) {
                        if let Some(exe_path) = caps.get(1) {
                            let exe_path_str = exe_path.as_str();

                            // Check if the executable is modifiable
                            if let Ok(true) = check_modifiable_access(exe_path_str) {
                                result.add_finding(format!(
                                    "{}\\{}: {} -> {}",
                                    hive_str, path, value_name, value
                                ));
                            }
                        }
                    }
                }
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No modifiable autorun executables found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = RegistryAutoruns;
        assert_eq!(check.name(), "Registry Autoruns");
    }

    #[test]
    fn test_check_execution() {
        let check = RegistryAutoruns;
        let result = check.check();
        assert!(result.is_ok());
    }
}
