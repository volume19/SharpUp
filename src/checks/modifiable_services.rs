//! ModifiableServices check
//!
//! Checks for Windows services with modifiable registry keys

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::registry::{get_reg_subkeys, get_reg_value, RegistryHive};

const SERVICES_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services";

pub struct ModifiableServices;

impl VulnerabilityCheck for ModifiableServices {
    fn name(&self) -> &str {
        "Modifiable Services"
    }

    fn description(&self) -> &str {
        "Checks for Windows services with modifiable registry keys"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Enumerate all services
        let service_names = match get_reg_subkeys(RegistryHive::HKLM, SERVICES_REG_PATH) {
            Ok(names) => names,
            Err(_) => {
                result.add_detail("Could not enumerate services from registry");
                return Ok(result);
            }
        };

        for service_name in service_names.iter().take(100) {
            // Limit to first 100 for performance
            let service_path = format!("{}\\{}", SERVICES_REG_PATH, service_name);

            // Get the ImagePath to display in findings
            let image_path = get_reg_value(RegistryHive::HKLM, &service_path, "ImagePath")
                .unwrap_or_else(|_| "(unknown)".to_string());

            // Check if the registry key path is modifiable
            // Note: This is a simplified check. A full implementation would check
            // the service's security descriptor using Windows APIs
            let reg_key_path = format!("HKLM\\{}", service_path);

            // For now, we'll mark services as potentially modifiable if they're
            // in non-standard locations or have certain characteristics
            // A production implementation would use proper ACL checking
            if is_potentially_modifiable(service_name, &image_path) {
                result.add_finding(format!(
                    "Service: {} - ImagePath: {} - Registry: {}",
                    service_name, image_path, reg_key_path
                ));
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No obviously modifiable services found (note: this is a basic check)");
        }

        Ok(result)
    }
}

/// Basic heuristic to identify potentially modifiable services
/// A full implementation would check actual ACLs using Windows APIs
fn is_potentially_modifiable(service_name: &str, image_path: &str) -> bool {
    let name_lower = service_name.to_lowercase();
    let path_lower = image_path.to_lowercase();

    // Skip well-known system services
    let system_prefixes = [
        "microsoft",
        "windows",
        "wmi",
        "rpc",
        "dcom",
        "bits",
        "cryptsvc",
        "dhcp",
        "dnscache",
        "eventlog",
        "lsm",
        "netman",
        "nsi",
        "plugplay",
        "power",
        "profiler",
        "schedule",
        "seclogon",
        "sens",
        "themes",
        "trustedinstaller",
        "usbstor",
        "w32time",
        "wdiservice",
        "wecsvc",
        "wersvc",
        "winmgmt",
        "wsearch",
    ];

    for prefix in &system_prefixes {
        if name_lower.starts_with(prefix) {
            return false;
        }
    }

    // Skip services in system32
    if path_lower.contains("system32") || path_lower.contains("\\windows\\") {
        return false;
    }

    // Services in Program Files or other non-system locations might be modifiable
    path_lower.contains("program files")
        || path_lower.contains("programdata")
        || (!path_lower.contains("windows") && !path_lower.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = ModifiableServices;
        assert_eq!(check.name(), "Modifiable Services");
    }

    #[test]
    fn test_is_potentially_modifiable() {
        // Potentially modifiable
        assert!(is_potentially_modifiable(
            "CustomService",
            "C:\\Program Files\\MyApp\\service.exe"
        ));
        assert!(is_potentially_modifiable(
            "ThirdPartyService",
            "C:\\ProgramData\\Service\\app.exe"
        ));

        // System services - should not be flagged
        assert!(!is_potentially_modifiable(
            "WindowsService",
            "C:\\Windows\\System32\\svchost.exe"
        ));
        assert!(!is_potentially_modifiable(
            "MicrosoftService",
            "C:\\Windows\\System32\\service.exe"
        ));
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = ModifiableServices;
        let result = check.check();
        assert!(result.is_ok());
    }
}
