//! Domain GPP Password check
//!
//! Searches domain SYSVOL for GPP XML files (requires domain context)

use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::error::CheckError;
use crate::utils::file::{find_files, parse_gpp_password_from_xml};

pub struct DomainGppPassword;

impl VulnerabilityCheck for DomainGppPassword {
    fn name(&self) -> &str {
        "Domain GPP Password"
    }

    fn description(&self) -> &str {
        "Checks domain SYSVOL for Group Policy Preferences passwords"
    }

    fn check(&self) -> Result<CheckResult, CheckError> {
        let mut result = CheckResult::new(self.name());

        // Get domain name from environment
        let domain = match std::env::var("USERDNSDOMAIN") {
            Ok(d) if !d.is_empty() => d,
            _ => {
                result.add_detail("Not in a domain environment");
                return Ok(result);
            }
        };

        // Construct SYSVOL path
        let sysvol_path = format!("\\\\{}\\SYSVOL\\{}\\Policies", domain, domain);

        // Search for GPP XML files in SYSVOL
        let files = find_files(&sysvol_path, &["*.xml"]);

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
            result.add_detail(format!("No GPP passwords found in {} SYSVOL", domain));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_instantiation() {
        let check = DomainGppPassword;
        assert_eq!(check.name(), "Domain GPP Password");
    }

    #[test]
    fn test_check_execution() {
        let check = DomainGppPassword;
        let result = check.check();
        assert!(result.is_ok());
    }
}
