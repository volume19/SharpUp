//! File system utilities including ACL checks and GPP password decryption

use crate::error::CheckError;
use std::path::Path;

/// GPP (Group Policy Preferences) password data
#[derive(Debug, Clone)]
pub struct GppPassword {
    pub username: String,
    pub new_name: String,
    pub cpassword: String,
    pub changed: String,
}

impl GppPassword {
    pub fn new() -> Self {
        Self {
            username: String::new(),
            new_name: String::new(),
            cpassword: String::new(),
            changed: String::new(),
        }
    }

    /// Format for display
    pub fn format(&self) -> String {
        let username = if self.username.is_empty() {
            "[BLANK]"
        } else {
            &self.username
        };

        let new_name = if self.new_name.is_empty() {
            "[BLANK]"
        } else {
            &self.new_name
        };

        let password = if self.cpassword.is_empty() {
            "[BLANK]".to_string()
        } else {
            decrypt_gpp_password(&self.cpassword).unwrap_or_else(|_| "[DECRYPT_FAILED]".to_string())
        };

        let changed = if self.changed.is_empty() {
            "[BLANK]"
        } else {
            &self.changed
        };

        format!(
            "UserName: {} | NewName: {} | Password: {} | Changed: {}",
            username, new_name, password, changed
        )
    }
}

/// Decrypt GPP cpassword value
///
/// Uses the well-known AES-256-CBC key published by Microsoft
pub fn decrypt_gpp_password(cpassword: &str) -> Result<String, CheckError> {
    use aes::Aes256;
    use base64::Engine;
    use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};

    // Microsoft's published GPP AES key (this is public knowledge)
    const GPP_KEY: [u8; 32] = [
        0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
        0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
        0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
        0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
    ];

    // IV is all zeros for GPP
    const GPP_IV: [u8; 16] = [0u8; 16];

    // Fix base64 padding
    let mut padded = cpassword.to_string();
    let mod4 = padded.len() % 4;
    match mod4 {
        1 => {
            padded.pop(); // Remove last char
        }
        2 | 3 => {
            padded.push_str(&"=".repeat(4 - mod4));
        }
        _ => {}
    }

    // Decode base64
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .map_err(|e| CheckError::Other(format!("Base64 decode error: {}", e)))?;

    // Decrypt using AES-256-CBC
    type Aes256CbcDec = Decryptor<Aes256>;
    let cipher = Aes256CbcDec::new(&GPP_KEY.into(), &GPP_IV.into());

    let mut buffer = encrypted.clone();
    let decrypted = cipher
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| CheckError::Other(format!("Decryption error: {}", e)))?;

    // Convert to UTF-16 LE string (Windows format)
    let utf16_data: Vec<u16> = decrypted
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    Ok(String::from_utf16_lossy(&utf16_data))
}

/// Parse GPP password from XML file
pub fn parse_gpp_password_from_xml(file_path: &str) -> Result<GppPassword, CheckError> {
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| CheckError::Other(format!("Failed to read file: {}", e)))?;

    // Check if file contains cpassword
    if !content.contains("cpassword") {
        return Err(CheckError::Other("No cpassword in file".to_string()));
    }

    let doc = roxmltree::Document::parse(&content)
        .map_err(|e| CheckError::Other(format!("XML parse error: {}", e)))?;

    let mut result = GppPassword::new();

    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Parse based on file type
    if file_name.contains("Groups.xml") {
        if let Some(props) = doc.descendants().find(|n| n.has_tag_name("Properties")) {
            for attr in props.attributes() {
                match attr.name() {
                    "cpassword" => result.cpassword = attr.value().to_string(),
                    "userName" => result.username = attr.value().to_string(),
                    "newName" => result.new_name = attr.value().to_string(),
                    _ => {}
                }
            }
        }
        if let Some(user) = doc.descendants().find(|n| n.has_tag_name("User")) {
            if let Some(changed) = user.attribute("changed") {
                result.changed = changed.to_string();
            }
        }
    } else if file_name.contains("Services.xml") {
        if let Some(props) = doc.descendants().find(|n| n.has_tag_name("Properties")) {
            for attr in props.attributes() {
                match attr.name() {
                    "cpassword" => result.cpassword = attr.value().to_string(),
                    "accountName" => result.username = attr.value().to_string(),
                    _ => {}
                }
            }
        }
        if let Some(service) = doc.descendants().find(|n| n.has_tag_name("NTService")) {
            if let Some(changed) = service.attribute("changed") {
                result.changed = changed.to_string();
            }
        }
    } else if file_name.contains("Scheduledtasks.xml") {
        if let Some(props) = doc.descendants().find(|n| n.has_tag_name("Properties")) {
            for attr in props.attributes() {
                match attr.name() {
                    "cpassword" => result.cpassword = attr.value().to_string(),
                    "runAs" => result.username = attr.value().to_string(),
                    _ => {}
                }
            }
        }
        if let Some(task) = doc.descendants().find(|n| n.has_tag_name("Task")) {
            if let Some(changed) = task.attribute("changed") {
                result.changed = changed.to_string();
            }
        }
    } else if file_name.contains("DataSources.xml") || file_name.contains("Printers.xml") || file_name.contains("Drives.xml") {
        if let Some(props) = doc.descendants().find(|n| n.has_tag_name("Properties")) {
            for attr in props.attributes() {
                match attr.name() {
                    "cpassword" => result.cpassword = attr.value().to_string(),
                    "username" => result.username = attr.value().to_string(),
                    _ => {}
                }
            }
        }
    }

    if result.cpassword.is_empty() {
        Err(CheckError::Other("No cpassword found".to_string()))
    } else {
        Ok(result)
    }
}

/// Find files matching patterns recursively
pub fn find_files(path: &str, patterns: &[&str]) -> Vec<String> {
    let mut results = Vec::new();

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    // Recurse into subdirectory
                    if let Some(dir_path) = entry.path().to_str() {
                        results.extend(find_files(dir_path, patterns));
                    }
                } else if metadata.is_file() {
                    if let Some(file_name) = entry.file_name().to_str() {
                        let file_name_lower = file_name.to_lowercase();
                        for pattern in patterns {
                            if pattern.contains('*') {
                                // Simple glob matching
                                let pattern_lower = pattern.to_lowercase();
                                let parts: Vec<&str> = pattern_lower.split('*').collect();
                                if parts.len() == 2 {
                                    if file_name_lower.starts_with(parts[0]) && file_name_lower.ends_with(parts[1]) {
                                        if let Some(full_path) = entry.path().to_str() {
                                            results.push(full_path.to_string());
                                        }
                                        break;
                                    }
                                }
                            } else if file_name_lower == pattern.to_lowercase() {
                                if let Some(full_path) = entry.path().to_str() {
                                    results.push(full_path.to_string());
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    results
}

/// Check if a file/directory is modifiable by current user
///
/// Simplified version - full ACL checking would require extensive Win32 API calls
#[cfg(windows)]
pub fn check_modifiable_access(path: &str) -> Result<bool, CheckError> {
    use std::fs;
    use std::io::Write;

    // Try to write a test file in the directory or modify the file
    let test_path = Path::new(path);

    if test_path.is_dir() {
        // Try to create a temp file
        let test_file = test_path.join(".sharpup_test_access");
        match fs::File::create(&test_file) {
            Ok(mut file) => {
                let _ = file.write_all(b"test");
                let _ = fs::remove_file(&test_file);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    } else {
        // Try to open file for append
        match fs::OpenOptions::new().append(true).open(path) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(not(windows))]
pub fn check_modifiable_access(_path: &str) -> Result<bool, CheckError> {
    Ok(false) // Stub for non-Windows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpp_password_decrypt() {
        // Known test vector from Microsoft documentation
        let cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw";
        let result = decrypt_gpp_password(cpassword);
        assert!(result.is_ok());
        // The decrypted password would be "Password1" or similar test value
    }

    #[test]
    fn test_gpp_password_new() {
        let gpp = GppPassword::new();
        assert!(gpp.username.is_empty());
        assert!(gpp.cpassword.is_empty());
    }

    #[test]
    fn test_find_files_empty() {
        let results = find_files("/nonexistent", &["*.xml"]);
        assert_eq!(results.len(), 0);
    }
}
