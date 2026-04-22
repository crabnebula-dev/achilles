//! Chromium-based browser probe.
//!
//! Standalone Chromium browsers (Chrome itself, Arc, Brave, Edge, …) ship
//! `<Vendor> (Framework)?.framework/` under `Contents/Frameworks/`. These
//! aren't Electron and they aren't CEF — they're the full browser shell.
//! Flagging them is mostly defensive: users probably know Chrome is a
//! browser, but the runtime-CVE columns should still populate.

use std::path::Path;

/// Known framework directory suffixes for Chromium-based browsers. Matched
/// as substrings against entries in `Contents/Frameworks/`.
const MARKERS: &[&str] = &[
    "Google Chrome Framework.framework",
    "Chromium Framework.framework",
    "Brave Browser Framework.framework",
    "Microsoft Edge Framework.framework",
    "Arc Framework.framework",
    "Opera Framework.framework",
    "Vivaldi Framework.framework",
];

pub struct Detection {
    /// Chromium version, pulled from the browser-framework's Info.plist.
    pub chromium_version: Option<String>,
}

pub fn detect(app_path: &Path) -> Option<Detection> {
    let frameworks_dir = app_path.join("Contents/Frameworks");
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
    for rel in &[
        "Versions/A/Resources/Info.plist",
        "Resources/Info.plist",
    ] {
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
