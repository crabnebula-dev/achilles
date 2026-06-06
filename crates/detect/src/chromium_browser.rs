//! Chromium-based browser probe.
//!
//! Standalone Chromium browsers (Chrome, Arc, Brave, Edge, Vivaldi, Opera, …)
//! aren't Electron and aren't CEF — they're the full browser shell. Flagging
//! them is mostly defensive, but the runtime-CVE columns should still
//! populate.
//!
//! * **macOS**: a `<Vendor> Framework.framework` under `Contents/Frameworks/`;
//!   the version is in its Info.plist.
//! * **Windows / Linux**: a known browser executable name next to Chromium
//!   support files (`*.pak` / `icudtl.dat`); the version is string-scanned from
//!   the binary's `Chrome/<version>` UA marker.

use crate::app::Layout;

pub struct Detection {
    /// Chromium version, from the browser framework's Info.plist (macOS) or the
    /// binary's UA string (Windows / Linux).
    pub chromium_version: Option<String>,
}

/// Known Chromium-browser executable basenames (lower-cased, without the
/// platform `.exe` suffix).
#[allow(dead_code)] // matched by the non-macOS browser probe
const BROWSER_BINARIES: &[&str] = &[
    "chrome",
    "msedge",
    "brave",
    "arc",
    "opera",
    "vivaldi",
    "chromium",
    "chromium-browser",
    "thorium",
    "yandex",
];

pub fn detect(layout: &Layout) -> Option<Detection> {
    #[cfg(target_os = "macos")]
    {
        macos::detect(layout)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let exe = layout.executable.as_deref()?;
        let stem = exe
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())?;
        if !BROWSER_BINARIES.contains(&stem.as_str()) {
            return None;
        }
        // Corroborate with Chromium support files so we don't flag an unrelated
        // binary that merely shares a name. Chrome ships `chrome_NNN_percent.pak`
        // rather than `resources.pak`, so accept any `.pak` plus `icudtl.dat`.
        if !has_chromium_support(&layout.root) {
            return None;
        }
        let chromium_version = crate::strings::scan_electron_versions(exe)
            .ok()
            .and_then(|(chromium, _)| chromium);
        Some(Detection { chromium_version })
    }
}

/// True if `dir` contains Chromium runtime support files (`icudtl.dat` or any
/// `.pak`).
#[cfg(not(target_os = "macos"))]
fn has_chromium_support(dir: &std::path::Path) -> bool {
    if dir.join("icudtl.dat").exists() {
        return true;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry
                .path()
                .extension()
                .map(|e| e.eq_ignore_ascii_case("pak"))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::Path;

    use super::*;

    /// Framework directory suffixes for Chromium-based browsers, matched as
    /// substrings against entries in `Contents/Frameworks/`.
    const MARKERS: &[&str] = &[
        "Google Chrome Framework.framework",
        "Chromium Framework.framework",
        "Brave Browser Framework.framework",
        "Microsoft Edge Framework.framework",
        "Arc Framework.framework",
        "Opera Framework.framework",
        "Vivaldi Framework.framework",
    ];

    pub fn detect(layout: &Layout) -> Option<Detection> {
        let frameworks_dir = layout.frameworks_dir();
        let entries = std::fs::read_dir(&frameworks_dir).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if !MARKERS.iter().any(|m| name_s.contains(m)) {
                continue;
            }
            let fw = entry.path();
            let chromium_version = read_chromium_version(&fw);
            return Some(Detection { chromium_version });
        }
        None
    }

    fn read_chromium_version(framework_dir: &Path) -> Option<String> {
        for rel in &["Versions/A/Resources/Info.plist", "Resources/Info.plist"] {
            let plist_path = framework_dir.join(rel);
            if !plist_path.exists() {
                continue;
            }
            let Ok(value) = plist::Value::from_file(&plist_path) else {
                continue;
            };
            let Some(dict) = value.as_dictionary() else {
                continue;
            };
            if let Some(v) = dict
                .get("CFBundleShortVersionString")
                .or_else(|| dict.get("CFBundleVersion"))
                .and_then(|v| v.as_string())
            {
                return Some(v.to_owned());
            }
        }
        None
    }
}
