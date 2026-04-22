//! Safari / WKWebView probe.
//!
//! Two distinct uses:
//!
//! 1. **Primary verdict**: if the bundle-id is `com.apple.Safari`, the app
//!    is Safari and the version comes from the bundle's own Info.plist.
//! 2. **System WKWebView signal**: the Safari version installed at
//!    `/Applications/Safari.app` (or `/System/Applications/Safari.app`) is
//!    the effective WebKit engine version for every Tauri / Wails / other
//!    WKWebView-backed app on the machine. We expose that separately so
//!    those apps can surface it in their detail pane.
//!
//! WKWebView isn't a per-app runtime — it's a system framework — so there's
//! no version to read from any individual bundle. The Safari version is the
//! closest usable proxy (and NVD keys WebKit CVEs to `apple:safari`
//! anyway).

use std::path::Path;
use std::sync::OnceLock;

/// Cache the system Safari version per process — it never changes during a
/// scan, and hitting the filesystem once per bundle would be wasteful.
static SYSTEM_WEBKIT: OnceLock<Option<String>> = OnceLock::new();

const SYSTEM_SAFARI_PATHS: &[&str] = &[
    "/Applications/Safari.app",
    "/System/Applications/Safari.app",
    "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app",
];

/// Return `Some(version)` if this bundle *is* Safari.
pub fn detect_app(bundle_id: Option<&str>, app_path: &Path) -> Option<String> {
    if bundle_id != Some("com.apple.Safari") {
        return None;
    }
    read_bundle_version(app_path)
}

/// The effective WKWebView version on this machine — Safari's Info.plist
/// `CFBundleShortVersionString`. Memoised for the process lifetime.
pub fn system_webkit_version() -> Option<String> {
    SYSTEM_WEBKIT.get_or_init(locate_system_safari_version).clone()
}

fn locate_system_safari_version() -> Option<String> {
    for candidate in SYSTEM_SAFARI_PATHS {
        let path = Path::new(candidate);
        if !path.is_dir() {
            continue;
        }
        if let Some(v) = read_bundle_version(path) {
            return Some(v);
        }
    }
    None
}

fn read_bundle_version(app_path: &Path) -> Option<String> {
    let plist_path = app_path.join("Contents/Info.plist");
    let value = plist::Value::from_file(&plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
