//! CEF (Chromium Embedded Framework) probe.
//!
//! CEF ships its own runtime, independent of Electron. An app can be *both*
//! Tauri and CEF, so this probe runs regardless of the primary verdict.
//!
//! We report the **embedded Chromium build** (e.g. `147.0.7727.138`) so it can
//! be matched against Chromium CVEs (`cpe:2.3:a:google:chrome:*`).
//!
//! * **macOS**: `Contents/Frameworks/Chromium Embedded Framework.framework`.
//!   The plist's `CFBundleShortVersionString` is the *CEF* release version
//!   (e.g. `147.0.11.0`), which does **not** match Chromium CVE CPEs — so we
//!   string-scan the framework binary's `Chrome/<version>` UA marker for the
//!   real Chromium build, falling back to the plist only if that fails.
//! * **Windows / Linux**: `libcef.dll` / `libcef.so` beside the executable (or
//!   imported by it). The Chromium version is string-scanned from that library.

use crate::app::Layout;

/// Return the embedded Chromium build if the app embeds CEF, else `None`.
pub fn detect(layout: &Layout) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let framework_dir = layout
            .frameworks_dir()
            .join("Chromium Embedded Framework.framework");
        if !framework_dir.is_dir() {
            return None;
        }
        // Prefer the real Chromium build scanned from the framework binary's
        // UA string. The binary lives at the framework root (a symlink into
        // `Versions/Current`) on a normal layout; try the versioned paths too.
        for bin in &[
            "Chromium Embedded Framework",
            "Versions/Current/Chromium Embedded Framework",
            "Versions/A/Chromium Embedded Framework",
        ] {
            let path = framework_dir.join(bin);
            if path.is_file() {
                if let Some(v) = crate::strings::scan_electron_versions(&path)
                    .ok()
                    .and_then(|(chromium, _)| chromium)
                {
                    return Some(v);
                }
            }
        }
        // Fall back to the plist's CEF version if the scan found nothing —
        // better than no signal, though it won't match Chromium CVE CPEs.
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
