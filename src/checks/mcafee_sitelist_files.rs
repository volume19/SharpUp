//! McAfee SiteList.xml check
//!
//! Searches for McAfee SiteList.xml files which may contain encrypted passwords

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::find_files;

pub struct McAfeeSitelistFiles;

impl VulnerabilityCheck for McAfeeSitelistFiles {
    fn name(&self) -> &str {
        "McAfee SiteList.xml Files"
    }

    fn description(&self) -> &str {
        "Searches for McAfee SiteList.xml files with encrypted passwords"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Get system drive
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());

        // Search locations
        let search_locations = vec![
            format!("{}\\Program Files\\", drive),
            format!("{}\\Program Files (x86)\\", drive),
            format!("{}\\ProgramData\\", drive),
            format!("{}\\Users\\", drive),
        ];

        let mut found_files = Vec::new();

        for location in search_locations {
            let files = find_files(&location, &["SiteList.xml"]);
            found_files.extend(files);
        }

        if !found_files.is_empty() {
            for file in found_files {
                result.add_finding(format!("Found: {}", file));
                result.add_finding("Note: Decrypt with https://github.com/funoverip/mcafee-sitelist-pwd-decryption");
            }
        } else {
            result.add_detail("No McAfee SiteList.xml files found");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = McAfeeSitelistFiles;
        assert_eq!(check.name(), "McAfee SiteList.xml Files");
    }

    #[test]
    fn test_check_execution() {
        let check = McAfeeSitelistFiles;
        let result = check.check();
        assert!(result.is_ok());
    }
}
