//! Verify `ElectronAsarIntegrity` hashes against the archives on disk.
//!
//! Despite what Electron's docs suggest, the `hash` field in Info.plist is
//! *not* a whole-file SHA-256 — it's the SHA-256 of the ASAR archive's **JSON
//! header string**, excluding the two pickle length prefixes that wrap it on
//! disk. Empirically verified against multiple signed bundles.
//!
//! ASAR on-disk layout:
//!
//! ```text
//!   offset  0: u32 le  = 4           // pickle outer size (always 4)
//!   offset  4: u32 le  = header_size // bytes following this field that belong to the header
//!   offset  8: u32 le  = json_pickle_size
//!   offset 12: u32 le  = json_len    // length of the JSON string in bytes
//!   offset 16: json_len bytes        // the JSON header — THIS is what gets hashed
//!   …padding to 4-byte align…
//!   …file bodies…
//! ```
//!
//! We surface the declared hash, the actual hash, and a `matches` boolean
//! per archive so the UI can distinguish "integrity is intact" from
//! "someone modified app.asar after signing."

use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct AsarIntegrityCheck {
    /// Path relative to `Contents/`, as keyed in `ElectronAsarIntegrity`.
    pub archive_key: String,
    /// Absolute path of the archive on disk.
    pub archive_path: PathBuf,
    pub declared_algorithm: String,
    pub declared_hash: String,
    /// `None` if we couldn't read the file.
    pub actual_hash: Option<String>,
    pub matches: bool,
}

/// Returns `None` if the bundle has no `ElectronAsarIntegrity` entry (i.e.
/// it's not an Electron app, or it's an Electron app with integrity
/// disabled).
pub fn verify_all(app_path: &Path) -> Option<Vec<AsarIntegrityCheck>> {
    let plist_path = app_path.join("Contents/Info.plist");
    let value = plist::Value::from_file(&plist_path).ok()?;
    let dict = value.into_dictionary()?;
    let integrity = dict.get("ElectronAsarIntegrity")?.as_dictionary()?;

    let mut checks = Vec::new();
    for (key, entry) in integrity {
        let Some(entry) = entry.as_dictionary() else {
            continue;
        };
        let declared_algorithm = entry
            .get("algorithm")
            .and_then(|v| v.as_string())
            .unwrap_or("SHA256")
            .to_owned();
        let declared_hash = match entry.get("hash").and_then(|v| v.as_string()) {
            Some(h) => h.to_owned(),
            None => continue,
        };

        let archive_path = app_path.join("Contents").join(key);
        let actual_hash = match declared_algorithm.as_str() {
            "SHA256" => sha256_asar_header(&archive_path).ok(),
            _ => None,
        };

        let matches = actual_hash
            .as_deref()
            .map(|a| a.eq_ignore_ascii_case(&declared_hash))
            .unwrap_or(false);

        checks.push(AsarIntegrityCheck {
            archive_key: key.clone(),
            archive_path,
            declared_algorithm,
            declared_hash,
            actual_hash,
            matches,
        });
    }

    Some(checks)
}

/// SHA-256 of the ASAR header JSON string. See the module docs for layout.
fn sha256_asar_header(path: &Path) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind, Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;

    // We need four little-endian u32s starting at offset 0.
    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix)?;

    let outer = u32::from_le_bytes(prefix[0..4].try_into().unwrap());
    let _header_size = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
    let _json_pickle_size = u32::from_le_bytes(prefix[8..12].try_into().unwrap());
    let json_len = u32::from_le_bytes(prefix[12..16].try_into().unwrap()) as usize;

    if outer != 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("expected pickle outer=4, got {outer}"),
        ));
    }

    // Sanity cap: the header is a JSON directory, rarely more than ~100MB.
    const MAX_HEADER: usize = 256 * 1024 * 1024;
    if json_len > MAX_HEADER {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("implausible asar header length: {json_len}"),
        ));
    }

    file.seek(SeekFrom::Start(16))?;
    let mut json_buf = vec![0u8; json_len];
    file.read_exact(&mut json_buf)?;

    let mut hasher = Sha256::new();
    hasher.update(&json_buf);
    Ok(format!("{:x}", hasher.finalize()))
}
