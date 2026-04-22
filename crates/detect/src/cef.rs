//! CEF (Chromium Embedded Framework) probe.
//!
//! CEF ships its own framework bundle, independent of Electron. An app can
//! be *both* Tauri and CEF (rare — Tauri normally uses the system WKWebView,
//! but some apps bundle CEF alongside for features WKWebView can't do).
//! We therefore run this probe regardless of the primary framework verdict.
//!
//! CEF's Info.plist exposes the CEF/Chromium version as `CFBundleShortVersionString`,
//! typically formatted like `130.1.18+g5e85b92+chromium-130.0.6723.117`.

use std::path::Path;

const FRAMEWORK_REL: &str = "Contents/Frameworks/Chromium Embedded Framework.framework";

/// Return the CEF version string if the bundle contains a CEF framework,
/// else `None`. Looks at both versioned (`Versions/A/...`) and flat
/// layouts, matching [`crate::electron`]'s probe.
pub fn detect(app_path: &Path) -> Option<String> {
    let framework_dir = app_path.join(FRAMEWORK_REL);
    if !framework_dir.is_dir() {
        return None;
    }
    // Try versioned layout first, then flat.
    for rel in &["Versions/A/Resources/Info.plist", "Resources/Info.plist"] {
        let plist_path = framework_dir.join(rel);
        if !plist_path.exists() {
            continue;
        }
        if let Some(v) = read_version(&plist_path) {
            return Some(v);
        }
    }
    // Framework present but no parseable Info.plist — return a placeholder
    // so callers can still flag the bundle's CEF presence.
    Some("unknown".to_string())
}

fn read_version(plist_path: &Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
