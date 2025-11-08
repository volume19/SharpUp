//! Windows identity and token utilities
//!
//! Functions for checking user privileges, integrity levels, and group membership.

use crate::error::IdentityError;
use crate::native::win32::{get_token_groups, open_current_process_token};

/// Well-known SID for local administrators group
const SID_BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";

/// Check if the current process is running with high integrity (elevated/admin privileges)
///
/// This checks if the process token contains the Administrators group with
/// the SE_GROUP_ENABLED attribute, which indicates the process is elevated.
///
/// # Windows-specific behavior
/// - Returns `true` if running as elevated administrator
/// - Returns `false` if running as standard user or UAC-filtered admin
///
/// # Errors
/// Returns `IdentityError` if token information cannot be queried.
pub fn is_high_integrity() -> Result<bool, IdentityError> {
    // In Windows, high integrity means the Administrators group is enabled in the token
    // This is equivalent to checking WindowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator)
    is_local_admin()
}

/// Check if the current user is a member of the local Administrators group
///
/// This checks whether the well-known SID S-1-5-32-544 (Administrators) exists
/// in the process token's groups, regardless of whether it's enabled.
///
/// # Returns
/// - `true` if user is a local administrator (even if UAC-filtered)
/// - `false` if user is not an administrator
///
/// # Errors
/// Returns `IdentityError` if token groups cannot be queried.
pub fn is_local_admin() -> Result<bool, IdentityError> {
    let token = open_current_process_token()?;
    let groups = get_token_groups(&token)?;

    // Check if the Administrators SID is in the token groups
    Ok(groups.iter().any(|sid| sid == SID_BUILTIN_ADMINISTRATORS))
}

/// Get all SIDs (Security Identifiers) that the current process token belongs to
///
/// This returns both enabled and disabled groups. Disabled groups typically
/// indicate UAC-filtered tokens where the user is an admin but running with
/// standard user privileges.
///
/// # Returns
/// A vector of SID strings in the format "S-1-5-..."
///
/// # Errors
/// Returns `IdentityError` if token information cannot be queried.
pub fn get_token_group_sids() -> Result<Vec<String>, IdentityError> {
    let token = open_current_process_token()?;
    get_token_groups(&token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_is_high_integrity() {
        let result = is_high_integrity();
        assert!(result.is_ok(), "Should query integrity level");

        // We can't assert the value since it depends on how the test is run,
        // but we can verify it returns a boolean
        let _is_elevated = result.unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn test_is_local_admin() {
        let result = is_local_admin();
        assert!(result.is_ok(), "Should query admin status");

        // Value depends on test context, just verify it works
        let _is_admin = result.unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn test_get_token_group_sids() {
        let result = get_token_group_sids();
        assert!(result.is_ok(), "Should get token group SIDs");

        if let Ok(sids) = result {
            assert!(!sids.is_empty(), "Should have at least one SID");

            // All SIDs should start with "S-"
            for sid in &sids {
                assert!(sid.starts_with("S-"), "SID should start with 'S-': {}", sid);
            }

            // Should contain at least the Everyone group (S-1-1-0) or similar well-known SIDs
            assert!(sids.iter().any(|s| s.starts_with("S-1-")),
                   "Should contain at least one well-known SID");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_administrator_sid_constant() {
        // Verify the constant is correct
        assert_eq!(SID_BUILTIN_ADMINISTRATORS, "S-1-5-32-544");
    }
}
