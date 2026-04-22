//! Parse the top-level `Contents/Info.plist` of a macOS bundle.

use std::path::{Path, PathBuf};

/// The subset of `Contents/Info.plist` we care about.
#[derive(Debug, Clone, Default)]
pub struct BundleInfo {
    pub bundle_id: Option<String>,
    pub display_name: Option<String>,
    pub bundle_version: Option<String>,
    /// Absolute path to `Contents/MacOS/<CFBundleExecutable>`, if declared.
    /// Not verified to exist on disk — callers check before reading.
    pub executable: Option<PathBuf>,
}

/// Read and parse `Contents/Info.plist`. Missing or malformed plists return
/// [`BundleInfo::default`] rather than erroring — we want the scanner to keep
/// going.
pub fn read(app_path: &Path) -> BundleInfo {
    let plist_path = app_path.join("Contents/Info.plist");
    let Ok(value) = plist::Value::from_file(&plist_path) else {
        return BundleInfo::default();
    };
    let Some(dict) = value.as_dictionary() else {
        return BundleInfo::default();
    };

    let get = |key: &str| {
        dict.get(key)
            .and_then(|v| v.as_string())
            .map(str::to_owned)
    };

    let executable =
        get("CFBundleExecutable").map(|name| app_path.join("Contents/MacOS").join(name));

    BundleInfo {
        bundle_id: get("CFBundleIdentifier"),
        display_name: get("CFBundleDisplayName").or_else(|| get("CFBundleName")),
        bundle_version: get("CFBundleShortVersionString").or_else(|| get("CFBundleVersion")),
        executable,
    }
}
