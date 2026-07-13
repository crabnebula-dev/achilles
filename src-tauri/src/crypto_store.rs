//! Persist the latest crypto inventory (CBOM) per app, so the Cryptography
//! section retains its data across navigation and app restarts.
//!
//! One JSON file per app under `<data-dir>/achilles/crypto/<slug>.json`, keyed
//! by bundle id (falling back to the path basename).

use std::path::{Path, PathBuf};

fn store_dir() -> std::io::Result<PathBuf> {
    let base = dirs::data_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no data directory")
    })?;
    let dir = base.join("achilles").join("crypto");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn slug(path: &str, bundle_id: Option<&str>) -> String {
    let raw = bundle_id
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(path)
                .to_string()
        });
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "app".to_string()
    } else {
        s
    }
}

fn file_for(path: &str, bundle_id: Option<&str>) -> Option<PathBuf> {
    Some(store_dir().ok()?.join(format!("{}.json", slug(path, bundle_id))))
}

/// Persist the inventory for an app (best-effort; failures are ignored).
pub fn save(path: &str, bundle_id: Option<&str>, inventory: &cbom::CryptoInventory) {
    let Some(file) = file_for(path, bundle_id) else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(inventory) else {
        return;
    };
    let tmp = file.with_extension("json.tmp");
    if std::fs::write(&tmp, bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &file);
    }
}

/// Load the last persisted inventory for an app, if any.
pub fn load(path: &str, bundle_id: Option<&str>) -> Option<cbom::CryptoInventory> {
    let bytes = std::fs::read(file_for(path, bundle_id)?).ok()?;
    serde_json::from_slice(&bytes).ok()
}
