//! Safe wrappers around Windows API functions
//!
//! This module provides RAII handles and safe abstractions over
//! Win32 APIs used for privilege escalation enumeration.

use crate::error::{CheckError, IdentityError};
use std::ptr;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, LUID};
use windows::Win32::Security::{
    ConvertSidToStringSidW, GetTokenInformation, TokenGroups, TokenPrivileges, LUID_AND_ATTRIBUTES,
    SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Token access rights
pub const TOKEN_QUERY: u32 = 0x0008;

/// RAII wrapper for Windows HANDLE
pub struct SafeHandle(HANDLE);

impl SafeHandle {
    /// Create from raw handle
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    /// Get raw handle
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Check if handle is valid
    pub fn is_valid(&self) -> bool {
        !self.0.is_invalid()
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for LocalFree memory
pub struct LocalMemory(HLOCAL);

impl LocalMemory {
    pub fn new(ptr: HLOCAL) -> Self {
        Self(ptr)
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.0 .0 as *const u8
    }
}

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

/// Open the current process token
pub fn open_current_process_token() -> Result<SafeHandle, IdentityError> {
    unsafe {
        let mut token_handle = HANDLE::default();
        let result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle);

        if result.is_ok() {
            Ok(SafeHandle::new(token_handle))
        } else {
            Err(IdentityError::OpenTokenFailed)
        }
    }
}

/// Get token groups (SIDs) for a given token
pub fn get_token_groups(token: &SafeHandle) -> Result<Vec<String>, IdentityError> {
    unsafe {
        let mut return_length = 0u32;

        // First call to get required buffer size
        let _ = GetTokenInformation(
            token.as_raw(),
            TokenGroups,
            None,
            0,
            &mut return_length,
        );

        if return_length == 0 {
            return Err(IdentityError::QueryTokenFailed);
        }

        // Allocate buffer
        let mut buffer = vec![0u8; return_length as usize];

        // Second call to get actual data
        let result = GetTokenInformation(
            token.as_raw(),
            TokenGroups,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        );

        if result.is_err() {
            return Err(IdentityError::QueryTokenFailed);
        }

        // Parse TOKEN_GROUPS structure
        let token_groups = &*(buffer.as_ptr() as *const TOKEN_GROUPS);
        let mut sids = Vec::new();

        // Get array of SID_AND_ATTRIBUTES
        let groups_ptr = token_groups.Groups.as_ptr();
        let group_count = token_groups.GroupCount as usize;

        for i in 0..group_count {
            let sid_and_attr = &*groups_ptr.add(i);
            let sid_ptr = sid_and_attr.Sid;

            // Convert SID to string
            let mut string_sid = PWSTR::null();
            let result = ConvertSidToStringSidW(sid_ptr, &mut string_sid);

            if result.is_ok() {
                let sid_string = string_sid.to_string().map_err(|_| IdentityError::SidConversionFailed)?;
                sids.push(sid_string);

                // Free the string allocated by ConvertSidToStringSidW
                let _ = LocalFree(HLOCAL(string_sid.as_ptr() as *mut _));
            }
        }

        Ok(sids)
    }
}

/// Get token privileges for a given token
pub fn get_token_privileges(token: &SafeHandle) -> Result<Vec<(LUID, u32)>, IdentityError> {
    unsafe {
        let mut return_length = 0u32;

        // First call to get required buffer size
        let _ = GetTokenInformation(
            token.as_raw(),
            TokenPrivileges,
            None,
            0,
            &mut return_length,
        );

        if return_length == 0 {
            return Err(IdentityError::QueryTokenFailed);
        }

        // Allocate buffer
        let mut buffer = vec![0u8; return_length as usize];

        // Second call to get actual data
        let result = GetTokenInformation(
            token.as_raw(),
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        );

        if result.is_err() {
            return Err(IdentityError::QueryTokenFailed);
        }

        // Parse TOKEN_PRIVILEGES structure
        let token_privs = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let mut privileges = Vec::new();

        let privs_ptr = token_privs.Privileges.as_ptr();
        let priv_count = token_privs.PrivilegeCount as usize;

        for i in 0..priv_count {
            let luid_and_attr = &*privs_ptr.add(i);
            privileges.push((luid_and_attr.Luid, luid_and_attr.Attributes));
        }

        Ok(privileges)
    }
}

/// Convert LUID to privilege name
pub fn luid_to_name(luid: &LUID) -> Result<String, IdentityError> {
    use windows::Win32::Security::Authorization::LookupPrivilegeNameW;

    unsafe {
        let mut name_len = 0u32;

        // First call to get buffer size
        let _ = LookupPrivilegeNameW(None, luid, PWSTR::null(), &mut name_len);

        if name_len == 0 {
            return Err(IdentityError::InvalidData);
        }

        // Allocate buffer
        let mut name_buffer = vec![0u16; name_len as usize];

        // Second call to get name
        let result = LookupPrivilegeNameW(
            None,
            luid,
            PWSTR(name_buffer.as_mut_ptr()),
            &mut name_len,
        );

        if result.is_err() {
            return Err(IdentityError::InvalidData);
        }

        // Convert to String
        let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_current_token() {
        let token = open_current_process_token();
        assert!(token.is_ok(), "Should be able to open current process token");

        if let Ok(t) = token {
            assert!(t.is_valid(), "Token handle should be valid");
        }
    }

    #[test]
    fn test_get_token_groups() {
        let token = open_current_process_token().expect("Failed to open token");
        let groups = get_token_groups(&token);
        assert!(groups.is_ok(), "Should get token groups");

        if let Ok(g) = groups {
            assert!(!g.is_empty(), "Should have at least one group");
            // All SIDs should start with S-
            assert!(g.iter().all(|s| s.starts_with("S-")));
        }
    }

    #[test]
    fn test_get_token_privileges() {
        let token = open_current_process_token().expect("Failed to open token");
        let privs = get_token_privileges(&token);
        assert!(privs.is_ok(), "Should get token privileges");

        if let Ok(p) = privs {
            assert!(!p.is_empty(), "Should have at least one privilege");
        }
    }

    #[test]
    fn test_luid_to_name() {
        let token = open_current_process_token().expect("Failed to open token");
        let privs = get_token_privileges(&token).expect("Failed to get privileges");

        if let Some((luid, _)) = privs.first() {
            let name = luid_to_name(luid);
            assert!(name.is_ok(), "Should convert LUID to name");

            if let Ok(n) = name {
                assert!(!n.is_empty(), "Privilege name should not be empty");
            }
        }
    }
}
