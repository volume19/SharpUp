//! Windows Registry access utilities
//!
//! Safe wrappers for registry operations including reads and ACL checks.

use crate::error::RegistryError;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, REG_NONE, REG_SZ, RRF_RT_REG_SZ,
};

/// Windows registry hive
#[derive(Debug, Clone, Copy)]
pub enum RegistryHive {
    HKLM,
    HKCU,
    HKU,
}

impl RegistryHive {
    fn to_hkey(&self) -> HKEY {
        match self {
            RegistryHive::HKLM => HKEY_LOCAL_MACHINE,
            RegistryHive::HKCU => HKEY_CURRENT_USER,
            RegistryHive::HKU => HKEY_USERS,
        }
    }
}

/// RAII wrapper for registry key handle
pub struct RegKey(HKEY);

impl RegKey {
    /// Open a registry key
    pub fn open(hive: RegistryHive, path: &str) -> Result<Self, RegistryError> {
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey = HKEY::default();
            let result = RegOpenKeyExW(
                hive.to_hkey(),
                PCWSTR(path_wide.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            );

            if result == WIN32_ERROR(ERROR_SUCCESS.0) {
                Ok(Self(hkey))
            } else {
                Err(RegistryError::KeyNotFound(path.to_string()))
            }
        }
    }

    /// Get raw HKEY
    pub fn as_raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// Get a single registry value as string
pub fn get_reg_value(
    hive: RegistryHive,
    path: &str,
    value_name: &str,
) -> Result<String, RegistryError> {
    let key = RegKey::open(hive, path)?;
    let value_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut data_size = 0u32;

        // First call to get size
        let result = RegGetValueW(
            key.as_raw(),
            PCWSTR::null(),
            PCWSTR(value_wide.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut data_size),
        );

        if result != WIN32_ERROR(ERROR_SUCCESS.0) {
            return Err(RegistryError::ValueNotFound(value_name.to_string()));
        }

        if data_size == 0 {
            return Ok(String::new());
        }

        // Allocate buffer and get data
        let mut buffer = vec![0u16; (data_size / 2) as usize];
        let mut actual_size = data_size;

        let result = RegGetValueW(
            key.as_raw(),
            PCWSTR::null(),
            PCWSTR(value_wide.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr() as *mut _),
            Some(&mut actual_size),
        );

        if result != WIN32_ERROR(ERROR_SUCCESS.0) {
            return Err(RegistryError::ValueNotFound(value_name.to_string()));
        }

        // Convert to String, removing null terminator
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Ok(String::from_utf16_lossy(&buffer[..len]))
    }
}

/// Get all subkey names under a registry path
pub fn get_reg_subkeys(hive: RegistryHive, path: &str) -> Result<Vec<String>, RegistryError> {
    let key = RegKey::open(hive, path)?;
    let mut subkeys = Vec::new();

    unsafe {
        let mut index = 0u32;
        loop {
            let mut name_buffer = [0u16; 256];
            let mut name_len = name_buffer.len() as u32;

            let result = RegEnumKeyExW(
                key.as_raw(),
                index,
                windows::core::PWSTR(name_buffer.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );

            if result != WIN32_ERROR(ERROR_SUCCESS.0) {
                break; // No more keys
            }

            let subkey_name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
            subkeys.push(subkey_name);
            index += 1;
        }
    }

    Ok(subkeys)
}

/// Check if current user can modify a registry key
///
/// Note: Full ACL checking requires parsing security descriptors.
/// This is a simplified check that will be enhanced in future iterations.
pub fn is_modifiable_key(_hive: RegistryHive, _path: &str) -> Result<bool, RegistryError> {
    // TODO: Implement full ACL checking similar to C# version
    // This requires parsing SECURITY_DESCRIPTOR and checking DACLs
    // For now, return false as conservative default
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_get_reg_value() {
        // Try to read a known Windows registry value
        let result = get_reg_value(
            RegistryHive::HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        );

        assert!(result.is_ok(), "Should read ProductName registry value");
        if let Ok(value) = result {
            assert!(!value.is_empty(), "ProductName should not be empty");
            assert!(value.contains("Windows"), "Should contain 'Windows'");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_get_reg_value_not_found() {
        let result = get_reg_value(
            RegistryHive::HKLM,
            r"SOFTWARE\NonExistentKey",
            "NonExistentValue",
        );

        assert!(result.is_err(), "Should fail for non-existent key");
    }

    #[test]
    #[cfg(windows)]
    fn test_get_reg_subkeys() {
        let result = get_reg_subkeys(RegistryHive::HKLM, r"SOFTWARE\Microsoft");

        assert!(result.is_ok(), "Should enumerate subkeys");
        if let Ok(keys) = result {
            assert!(!keys.is_empty(), "Microsoft key should have subkeys");
        }
    }

    #[test]
    fn test_registry_hive_conversion() {
        let _ = RegistryHive::HKLM.to_hkey();
        let _ = RegistryHive::HKCU.to_hkey();
        let _ = RegistryHive::HKU.to_hkey();
    }
}
