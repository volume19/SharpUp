//! Registry AutoLogon credential check
//!
//! Checks the Winlogon registry key for plaintext autologon credentials.
//! When autologon is configured, credentials may be stored in plaintext.

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::registry::{get_reg_value, RegistryHive};

const REG_WINLOGON: &str = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// Check for autologon credentials in registry
pub struct RegistryAutoLogons;

impl VulnerabilityCheck for RegistryAutoLogons {
    fn name(&self) -> &str {
        "Registry AutoLogons"
    }

    fn description(&self) -> &str {
        "Checks for plaintext autologon credentials in Winlogon registry"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Check for AutoAdminLogon enabled
        let auto_admin_logon = get_reg_value(RegistryHive::HKLM, REG_WINLOGON, "AutoAdminLogon");
        let is_enabled = matches!(auto_admin_logon, Ok(ref v) if v == "1");

        if !is_enabled {
            result.add_detail("AutoAdminLogon not enabled");
            return Ok(result);
        }

        // If enabled, try to retrieve credentials
        let default_domain = get_reg_value(RegistryHive::HKLM, REG_WINLOGON, "DefaultDomainName")
            .unwrap_or_else(|_| String::new());

        let default_user = get_reg_value(RegistryHive::HKLM, REG_WINLOGON, "DefaultUserName")
            .unwrap_or_else(|_| String::new());

        let default_password =
            get_reg_value(RegistryHive::HKLM, REG_WINLOGON, "DefaultPassword")
                .unwrap_or_else(|_| String::new());

        // Only report if we found actual credentials
        if !default_user.is_empty() || !default_password.is_empty() {
            result.add_finding("AutoAdminLogon is enabled");

            if !default_domain.is_empty() {
                result.add_finding(format!("DefaultDomainName: {}", default_domain));
            }

            if !default_user.is_empty() {
                result.add_finding(format!("DefaultUserName: {}", default_user));
            }

            if !default_password.is_empty() {
                result.add_finding(format!("DefaultPassword: {}", default_password));
            }
        } else {
            result.add_detail("AutoAdminLogon enabled but no credentials found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = RegistryAutoLogons;
        assert_eq!(check.name(), "Registry AutoLogons");
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = RegistryAutoLogons;
        let result = check.check();
        assert!(result.is_ok(), "Check should execute successfully");
    }
}
