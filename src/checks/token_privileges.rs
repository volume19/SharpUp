//! Token Privileges vulnerability check
//!
//! Enumerates the current process token's privileges and identifies those
//! that can be abused for privilege escalation.

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;

#[cfg(windows)]
use crate::native::win32::{get_token_privileges, luid_to_name, open_current_process_token};

/// Privileges that can be abused for privilege escalation
const SPECIAL_PRIVILEGES: &[&str] = &[
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeImpersonatePrivilege",
    "SeTcbPrivilege",
];

/// Privilege attribute flags
#[allow(dead_code)]
mod priv_attrs {
    pub const SE_PRIVILEGE_DISABLED: u32 = 0x00000000;
    pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;
    pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
    pub const SE_PRIVILEGE_REMOVED: u32 = 0x00000004;
    pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x80000000;
}

fn format_attributes(attrs: u32) -> String {
    let mut parts = Vec::new();

    if attrs & priv_attrs::SE_PRIVILEGE_ENABLED != 0 {
        parts.push("Enabled");
    }
    if attrs & priv_attrs::SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0 {
        parts.push("EnabledByDefault");
    }
    if attrs & priv_attrs::SE_PRIVILEGE_REMOVED != 0 {
        parts.push("Removed");
    }
    if attrs & priv_attrs::SE_PRIVILEGE_USED_FOR_ACCESS != 0 {
        parts.push("UsedForAccess");
    }
    if attrs == priv_attrs::SE_PRIVILEGE_DISABLED {
        parts.push("Disabled");
    }

    if parts.is_empty() {
        format!("0x{:08X}", attrs)
    } else {
        parts.join(", ")
    }
}

/// Check for abusable token privileges
pub struct TokenPrivileges;

impl VulnerabilityCheck for TokenPrivileges {
    fn name(&self) -> &str {
        "Abusable Token Privileges"
    }

    fn description(&self) -> &str {
        "Checks for token privileges that can be abused for privilege escalation"
    }

    #[cfg(windows)]
    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        let token = open_current_process_token()?;
        let privileges = get_token_privileges(&token)?;

        for (luid, attributes) in privileges {
            // Convert LUID to privilege name
            if let Ok(privilege_name) = luid_to_name(&luid) {
                // Check if this is a special/abusable privilege
                if SPECIAL_PRIVILEGES.contains(&privilege_name.as_str()) {
                    let attrs_str = format_attributes(attributes);
                    result.add_finding(format!("{}: {}", privilege_name, attrs_str));
                }
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No abusable privileges found");
        }

        Ok(result)
    }

    #[cfg(not(windows))]
    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());
        result.add_detail("Not supported on non-Windows platforms");
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = TokenPrivileges;
        assert_eq!(check.name(), "Abusable Token Privileges");
    }

    #[test]
    fn test_format_attributes() {
        assert_eq!(format_attributes(0), "Disabled");
        assert_eq!(format_attributes(2), "Enabled");
        assert_eq!(
            format_attributes(3),
            "Enabled, EnabledByDefault"
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_check_execution() {
        let check = TokenPrivileges;
        let result = check.check();
        assert!(result.is_ok(), "Check should execute successfully");

        if let Ok(r) = result {
            // Most processes have at least SeChangeNotifyPrivilege,
            // but that's not in our special list, so this might not be vulnerable
            assert_eq!(r.name, "Abusable Token Privileges");
        }
    }
}
