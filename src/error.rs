//! Error types for SharpUp

use thiserror::Error;

/// Top-level error type for check execution
#[derive(Error, Debug)]
pub enum CheckError {
    #[error("Windows API error: {0}")]
    WindowsApi(String),

    #[error("Registry error: {0}")]
    Registry(#[from] RegistryError),

    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),

    #[error("Identity/token error: {0}")]
    Identity(#[from] IdentityError),

    #[error("Access denied")]
    AccessDenied,

    #[error("Not supported on this platform")]
    NotSupported,

    #[error("{0}")]
    Other(String),
}

/// Registry operation errors
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Registry key not found: {0}")]
    KeyNotFound(String),

    #[error("Registry value not found: {0}")]
    ValueNotFound(String),

    #[error("Access denied to registry key: {0}")]
    AccessDenied(String),

    #[error("Invalid registry data")]
    InvalidData,
}

/// Identity and token operation errors
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Failed to open process token")]
    OpenTokenFailed,

    #[error("Failed to query token information")]
    QueryTokenFailed,

    #[error("Failed to convert SID")]
    SidConversionFailed,

    #[error("Invalid token data")]
    InvalidData,
}

/// File operation errors
#[derive(Error, Debug)]
pub enum FileError {
    #[error("File not found: {0}")]
    NotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Failed to parse ACL")]
    AclParseFailed,

    #[error("XML parse error: {0}")]
    XmlParse(String),

    #[error("Decryption error: {0}")]
    Decryption(String),
}
