//! Enumerate sub-bundles / sub-executables that live *inside* the app
//! bundle but aren't the main executable.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// One helper, plugin, or XPC service bundled inside the app.
#[derive(Debug, Clone, Serialize)]
pub struct BundleHelper {
    /// Name of the file or subdirectory (e.g. `chrome-native-host`,
    /// `Signal Helper.app`, `GPUProcess.xpc`).
    pub name: String,
    /// Absolute path.
    pub path: PathBuf,
    /// Total size in bytes (walks directories recursively for `.app`/`.xpc`
    /// bundles). `None` if we hit a permission issue.
    pub size_bytes: Option<u64>,
    /// Bundle id, if it's an `.app` / `.xpc` we could parse an
    /// `Info.plist` out of.
    pub bundle_id: Option<String>,
    /// Version string from the sub-bundle's Info.plist, if present.
    pub version: Option<String>,
    /// True if the entry is a `.app` or `.xpc` directory (i.e. a nested
    /// bundle rather than a raw executable).
    pub is_bundle: bool,
}

/// List every entry directly under `app_path/rel_dir`. Nested bundles get
/// their Info.plist read; plain executables just get a name/size/path.
pub fn enumerate(app_path: &Path, rel_dir: &str) -> Vec<BundleHelper> {
    let dir = app_path.join(rel_dir);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // skip .DS_Store, .localized, etc.
        }

        let is_bundle = name.ends_with(".app") || name.ends_with(".xpc");
        let size_bytes = if path.is_dir() {
            dir_size(&path).ok()
        } else {
            fs::metadata(&path).ok().map(|m| m.len())
        };

        let (bundle_id, version) = if is_bundle {
            read_bundle_id_and_version(&path)
        } else {
            (None, None)
        };

        out.push(BundleHelper {
            name,
            path,
            size_bytes,
            bundle_id,
            version,
            is_bundle,
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)?.flatten() {
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            total = total.saturating_add(dir_size(&entry.path()).unwrap_or(0));
        } else if file_type.is_file() {
            total = total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
        }
    }
    Ok(total)
}

fn read_bundle_id_and_version(bundle_path: &Path) -> (Option<String>, Option<String>) {
    let plist_path = bundle_path.join("Contents/Info.plist");
    let Ok(value) = plist::Value::from_file(&plist_path) else {
        return (None, None);
    };
    let Some(dict) = value.as_dictionary() else {
        return (None, None);
    };
    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .map(str::to_owned);
    let version = dict
        .get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned);
    (bundle_id, version)
}
