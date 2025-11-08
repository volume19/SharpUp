//! AlwaysInstallElevated privilege escalation check
//!
//! Checks if the Windows Installer "AlwaysInstallElevated" policy is enabled.
//! When both HKLM and HKCU keys are set to 1, any user can install MSI packages
//! with SYSTEM privileges.

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::registry::{get_reg_value, RegistryHive};

const REG_PATH: &str = r"Software\Policies\Microsoft\Windows\Installer";
const REG_NAME: &str = "AlwaysInstallElevated";

/// Check for AlwaysInstallElevated policy misconfiguration
pub struct AlwaysInstallElevated;

impl VulnerabilityCheck for AlwaysInstallElevated {
    fn name(&self) -> &str {
        "Always Install Elevated"
    }

    fn description(&self) -> &str {
        "Checks if MSI packages can be installed with elevated privileges"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Check HKLM policy
        let hklm_value = get_reg_value(RegistryHive::HKLM, REG_PATH, REG_NAME);
        let hklm_enabled = matches!(hklm_value, Ok(ref v) if v == "1");

        // Check HKCU policy
        let hkcu_value = get_reg_value(RegistryHive::HKCU, REG_PATH, REG_NAME);
        let hkcu_enabled = matches!(hkcu_value, Ok(ref v) if v == "1");

        // Both must be set for the vulnerability to be present
        if hklm_enabled && hkcu_enabled {
            result.add_finding("HKLM: 1");
            result.add_finding("HKCU: 1");
            result.add_finding(
                "Both policies are enabled - any user can install MSI with SYSTEM privileges",
            );
        } else if hklm_enabled {
            result.add_detail("HKLM: 1 (enabled)");
            result.add_detail("HKCU: Not set or disabled");
            result.add_detail("Not vulnerable - both policies must be enabled");
        } else if hkcu_enabled {
            result.add_detail("HKLM: Not set or disabled");
            result.add_detail("HKCU: 1 (enabled)");
            result.add_detail("Not vulnerable - both policies must be enabled");
        } else {
            result.add_detail("Not vulnerable - policy not enabled");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = AlwaysInstallElevated;
        assert_eq!(check.name(), "Always Install Elevated");
        assert!(!check.description().is_empty());
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = AlwaysInstallElevated;
        let result = check.check();

        // Should complete without error
        assert!(result.is_ok(), "Check should execute successfully");

        if let Ok(r) = result {
            assert_eq!(r.name, "Always Install Elevated");
            // Will typically not be vulnerable on standard systems
            // Just verify it returns a result
        }
    }
}
