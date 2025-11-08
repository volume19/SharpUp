//! SharpUp - Windows Privilege Escalation Enumeration Tool
//!
//! This is a Rust port of the C# SharpUp tool for identifying
//! privilege escalation vectors on Windows systems.
//!
//! **Intended for authorized security testing only.**

pub mod checks;
pub mod error;
pub mod native;

// Re-exports
pub use checks::{CheckResult, VulnerabilityCheck};
pub use error::CheckError;
