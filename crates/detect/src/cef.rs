//! CEF (Chromium Embedded Framework) probe.
//!
//! CEF ships its own runtime, independent of Electron. An app can be *both*
//! Tauri and CEF, so this probe runs regardless of the primary verdict.
//!
//! * **macOS**: `Contents/Frameworks/Chromium Embedded Framework.framework`,
//!   whose Info.plist exposes the version as `CFBundleShortVersionString`
//!   (e.g. `130.1.18+g5e85b92+chromium-130.0.6723.117`).
//! * **Windows / Linux**: `libcef.dll` / `libcef.so` beside the executable (or
//!   imported by it). The Chromium version is string-scanned from that library.

use crate::app::Layout;

/// Return the CEF version string if the app embeds CEF, else `None`.
pub fn detect(layout: &Layout) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let framework_dir = layout
            .frameworks_dir()
            .join("Chromium Embedded Framework.framework");
        if !framework_dir.is_dir() {
            return None;
        }
        for rel in &["Versions/A/Resources/Info.plist", "Resources/Info.plist"] {
            let plist_path = framework_dir.join(rel);
            if !plist_path.exists() {
                continue;
            }
            if let Some(v) = read_plist_version(&plist_path) {
                return Some(v);
            }
        }
        Some("unknown".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        if !layout.has_library("libcef") {
            return None;
        }
        // Scan the CEF library (or the main exe) for the Chromium UA version.
        let target = layout
            .find_file("libcef")
            .or_else(|| layout.executable.clone());
        let version = target
            .and_then(|p| crate::strings::scan_electron_versions(&p).ok())
            .and_then(|(chromium, _)| chromium);
        Some(version.unwrap_or_else(|| "unknown".to_string()))
    }
}

#[cfg(target_os = "macos")]
fn read_plist_version(plist_path: &std::path::Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
