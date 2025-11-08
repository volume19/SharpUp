//! Utility modules for system enumeration

#[cfg(windows)]
pub mod registry;

#[cfg(windows)]
pub mod identity;

#[cfg(not(windows))]
pub mod registry {
    //! Stub for non-Windows platforms
}

#[cfg(not(windows))]
pub mod identity {
    //! Stub for non-Windows platforms
}
