//! UnquotedServicePath check
//!
//! Checks for Windows services with unquoted paths containing spaces

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::check_modifiable_access;
use crate::utils::registry::{get_reg_subkeys, get_reg_value, RegistryHive};

const SERVICES_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services";

pub struct UnquotedServicePath;

impl VulnerabilityCheck for UnquotedServicePath {
    fn name(&self) -> &str {
        "Unquoted Service Paths"
    }

    fn description(&self) -> &str {
        "Checks for Windows services with unquoted paths containing spaces"
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

        for service_name in service_names {
            let service_path = format!("{}\\{}", SERVICES_REG_PATH, service_name);

            // Try to get ImagePath value
            let image_path = match get_reg_value(RegistryHive::HKLM, &service_path, "ImagePath") {
                Ok(path) => path,
                Err(_) => continue, // Skip services without ImagePath
            };

            // Check if path is vulnerable:
            // 1. Not quoted
            // 2. Contains spaces
            // 3. Points to an executable
            if is_vulnerable_path(&image_path) {
                // Extract the potential hijack paths
                if let Some(hijack_paths) = extract_hijack_paths(&image_path) {
                    for hijack_path in hijack_paths {
                        // Check if we can write to the hijack location
                        if let Ok(true) = check_modifiable_access(&hijack_path) {
                            result.add_finding(format!(
                                "Service: {} - ImagePath: {} - Modifiable: {}",
                                service_name, image_path, hijack_path
                            ));
                            break; // Only report once per service
                        }
                    }
                }
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No vulnerable unquoted service paths found");
        }

        Ok(result)
    }
}

/// Check if a path is vulnerable to unquoted service path exploitation
fn is_vulnerable_path(path: &str) -> bool {
    let trimmed = path.trim();

    // Skip if quoted
    if trimmed.starts_with('"') {
        return false;
    }

    // Skip if doesn't contain spaces
    if !trimmed.contains(' ') {
        return false;
    }

    // Skip if it's a system path or doesn't look like an executable path
    let lower = trimmed.to_lowercase();
    if !lower.contains(".exe") && !lower.contains(".dll") {
        return false;
    }

    // Skip common system directories that are not exploitable
    if lower.starts_with("system32") || lower.starts_with("\\systemroot") {
        return false;
    }

    true
}

/// Extract potential hijack paths from an unquoted service path
/// For example, "C:\Program Files\Some App\service.exe" could be hijacked at:
/// - C:\Program.exe
/// - C:\Program Files\Some.exe
fn extract_hijack_paths(path: &str) -> Option<Vec<String>> {
    let trimmed = path.trim();

    // Remove any arguments after .exe
    let exe_path = if let Some(exe_pos) = trimmed.to_lowercase().find(".exe") {
        &trimmed[..exe_pos + 4]
    } else {
        trimmed
    };

    let mut hijack_paths = Vec::new();
    let parts: Vec<&str> = exe_path.split('\\').collect();

    // Build potential hijack paths
    let mut current_path = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            current_path.push_str(part);
            continue;
        }

        // Check if this part contains a space
        if part.contains(' ') {
            // Split on first space and add .exe
            let space_parts: Vec<&str> = part.splitn(2, ' ').collect();
            if !space_parts.is_empty() {
                let hijack_path = format!("{}\\{}.exe", current_path, space_parts[0]);
                hijack_paths.push(hijack_path);
            }
        }

        current_path.push('\\');
        current_path.push_str(part);
    }

    if hijack_paths.is_empty() {
        None
    } else {
        Some(hijack_paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = UnquotedServicePath;
        assert_eq!(check.name(), "Unquoted Service Paths");
    }

    #[test]
    fn test_is_vulnerable_path() {
        // Vulnerable paths
        assert!(is_vulnerable_path("C:\\Program Files\\App\\service.exe"));
        assert!(is_vulnerable_path(
            "C:\\Program Files\\App\\service.exe -param"
        ));

        // Not vulnerable
        assert!(!is_vulnerable_path("\"C:\\Program Files\\App\\service.exe\""));
        assert!(!is_vulnerable_path("C:\\ProgramFiles\\App\\service.exe")); // No space
        assert!(!is_vulnerable_path("system32\\service.exe")); // System path
    }

    #[test]
    fn test_extract_hijack_paths() {
        let paths = extract_hijack_paths("C:\\Program Files\\Some App\\service.exe").unwrap();
        assert!(paths.contains(&"C:\\Program.exe".to_string()));
        assert!(paths.contains(&"C:\\Program Files\\Some.exe".to_string()));

        // Path with arguments
        let paths2 =
            extract_hijack_paths("C:\\Program Files\\Some App\\service.exe -arg").unwrap();
        assert!(paths2.contains(&"C:\\Program.exe".to_string()));

        // No hijack paths for properly formatted path
        assert!(extract_hijack_paths("C:\\ProgramFiles\\App\\service.exe").is_none());
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = UnquotedServicePath;
        let result = check.check();
        assert!(result.is_ok());
    }
}
