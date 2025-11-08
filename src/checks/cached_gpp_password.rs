//! Cached GPP Password check
//!
//! Searches local GPP cache for XML files containing encrypted passwords

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::{find_files, parse_gpp_password_from_xml};

pub struct CachedGppPassword;

impl VulnerabilityCheck for CachedGppPassword {
    fn name(&self) -> &str {
        "Cached GPP Password"
    }

    fn description(&self) -> &str {
        "Checks for cached Group Policy Preferences files with passwords"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Get AllUsersProfile path
        let mut all_users = std::env::var("ALLUSERSPROFILE")
            .unwrap_or_else(|_| "C:\\ProgramData".to_string());

        // Before Vista: C:\Documents and Settings\All Users
        if !all_users.contains("ProgramData") {
            all_users.push_str("\\Application Data");
        }

        all_users.push_str("\\Microsoft\\Group Policy\\History");

        // Search for GPP XML files
        let files = find_files(&all_users, &["*.xml"]);

        // Filter to relevant GPP files
        let gpp_files = [
            "Groups.xml",
            "Services.xml",
            "Scheduledtasks.xml",
            "DataSources.xml",
            "Printers.xml",
            "Drives.xml",
        ];

        for file in files {
            let file_name = std::path::Path::new(&file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if gpp_files.iter().any(|&gpp| file_name.contains(gpp)) {
                if let Ok(gpp_pass) = parse_gpp_password_from_xml(&file) {
                    result.add_finding(format!("Found in {}: {}", file, gpp_pass.format()));
                }
            }
        }

        if !result.is_vulnerable {
            result.add_detail("No cached GPP passwords found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = CachedGppPassword;
        assert_eq!(check.name(), "Cached GPP Password");
    }

    #[test]
    fn test_check_execution() {
        let check = CachedGppPassword;
        let result = check.check();
        assert!(result.is_ok());
    }
}
