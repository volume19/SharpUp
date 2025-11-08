//! Utility modules for system enumeration

#[cfg(windows)]
pub mod registry;
#[cfg(windows)]
pub mod identity;

// Re-export commonly used types
#[cfg(windows)]
pub use registry::{get_reg_subkeys, get_reg_value, RegistryHive};
#[cfg(windows)]
pub use identity::{get_token_group_sids, is_high_integrity, is_local_admin};

#[cfg(not(windows))]
pub mod registry {
    //! Stub for non-Windows platforms
    use crate::error::RegistryError;

    #[derive(Debug, Clone, Copy)]
    pub enum RegistryHive {
        HKLM,
        HKCU,
        HKU,
    }

    pub fn get_reg_value(
        _hive: RegistryHive,
        _path: &str,
        _value_name: &str,
    ) -> Result<String, RegistryError> {
        Err(RegistryError::KeyNotFound(
            "Registry access not supported on non-Windows platforms".to_string(),
        ))
    }

    pub fn get_reg_subkeys(_hive: RegistryHive, _path: &str) -> Result<Vec<String>, RegistryError> {
        Err(RegistryError::KeyNotFound(
            "Registry access not supported on non-Windows platforms".to_string(),
        ))
    }
}

#[cfg(not(windows))]
pub mod identity {
    //! Stub for non-Windows platforms
    use crate::error::IdentityError;

    pub fn is_high_integrity() -> Result<bool, IdentityError> {
        Err(IdentityError::QueryTokenFailed)
    }

    pub fn is_local_admin() -> Result<bool, IdentityError> {
        Err(IdentityError::QueryTokenFailed)
    }

    pub fn get_token_group_sids() -> Result<Vec<String>, IdentityError> {
        Err(IdentityError::QueryTokenFailed)
    }
}

#[cfg(not(windows))]
pub use registry::{get_reg_subkeys, get_reg_value, RegistryHive};
#[cfg(not(windows))]
pub use identity::{get_token_group_sids, is_high_integrity, is_local_admin};
