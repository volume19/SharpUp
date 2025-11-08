//! Windows native API wrappers

#[cfg(windows)]
pub mod win32;

#[cfg(not(windows))]
pub mod win32 {
    //! Stub implementations for non-Windows platforms
    use crate::error::CheckError;

    pub fn platform_not_supported() -> CheckError {
        CheckError::NotSupported
    }
}
