//! Vulnerability check trait and implementations

use crate::error::CheckError;

// Individual check modules
pub mod always_install_elevated;
pub mod registry_autologons;
pub mod unattended_install_files;

/// Result of a vulnerability check
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Name of the check
    pub name: String,
    /// Whether the system is vulnerable
    pub is_vulnerable: bool,
    /// Detailed findings
    pub details: Vec<String>,
}

impl CheckResult {
    /// Create a new check result
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_vulnerable: false,
            details: Vec::new(),
        }
    }

    /// Mark as vulnerable and add detail
    pub fn add_finding(&mut self, detail: impl Into<String>) {
        self.is_vulnerable = true;
        self.details.push(detail.into());
    }

    /// Add a detail without marking vulnerable
    pub fn add_detail(&mut self, detail: impl Into<String>) {
        self.details.push(detail.into());
    }
}

/// Trait for vulnerability checks
pub trait VulnerabilityCheck: Send + Sync {
    /// Name of this check
    fn name(&self) -> &str;

    /// Execute the check
    fn check(&self) -> Result<CheckResult, CheckError>;

    /// Short description of what this check does
    fn description(&self) -> &str {
        "No description available"
    }
}

/// Type alias for boxed vulnerability checks
pub type BoxedCheck = Box<dyn VulnerabilityCheck>;

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyCheck;

    impl VulnerabilityCheck for DummyCheck {
        fn name(&self) -> &str {
            "Dummy Check"
        }

        fn check(&self) -> Result<CheckResult, CheckError> {
            let mut result = CheckResult::new(self.name());
            result.add_finding("Test finding");
            Ok(result)
        }
    }

    #[test]
    fn test_check_result() {
        let mut result = CheckResult::new("Test");
        assert!(!result.is_vulnerable);
        assert_eq!(result.details.len(), 0);

        result.add_finding("Finding 1");
        assert!(result.is_vulnerable);
        assert_eq!(result.details.len(), 1);
    }

    #[test]
    fn test_dummy_check() {
        let check = DummyCheck;
        let result = check.check().unwrap();
        assert!(result.is_vulnerable);
        assert_eq!(result.details.len(), 1);
    }
}
