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
    #[cfg(macos_layout)]
    {
        macos::detect(layout)
    }
    #[cfg(not(macos_layout))]
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
#[cfg(not(macos_layout))]
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

#[cfg(macos_layout)]
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
        let entries = vfs::read_dir(&frameworks_dir).ok()?;
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

    /// Chrome-family frameworks keep one directory per installed version under
    /// `Versions/` (named by the version, e.g. `148.0.7778.216`), with a `Current`
    /// symlink pointing at the active one. After an update the *previous* version's
    /// directory lingers on disk, so we must not just grab the first entry — that
    /// risks reporting a stale leftover.
    ///
    /// Order of preference:
    ///   1. `Versions/Current` — the version Chrome will actually launch.
    ///   2. the framework's top-level `Resources` (usually another route to
    ///      `Current`).
    ///   3. the highest version directory present — covers a broken or missing
    ///      `Current` symlink without ever falling back to an older leftover.
    fn read_chromium_version(framework_dir: &Path) -> Option<String> {
        let versions_dir = framework_dir.join("Versions");

        if let Some(v) = read_plist_version(&versions_dir.join("Current/Resources/Info.plist")) {
            return Some(v);
        }
        if let Some(v) = read_plist_version(&framework_dir.join("Resources/Info.plist")) {
            return Some(v);
        }

        // Last resort: enumerate version directories and take the highest. The
        // directory name *is* the version; we still read its Info.plist when
        // possible, falling back to the directory name itself.
        let mut best: Option<String> = None;
        for entry in vfs::read_dir(&versions_dir).ok()?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip `Current` and anything that isn't a version directory.
            if !name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let version = read_plist_version(&entry.path().join("Resources/Info.plist"))
                .unwrap_or_else(|| name.into_owned());
            if best
                .as_deref()
                .map_or(true, |b| cmp_version(&version, b).is_gt())
            {
                best = Some(version);
            }
        }
        best
    }

    /// Read `CFBundleShortVersionString` (falling back to `CFBundleVersion`) from a
    /// plist, or `None` if the file is missing/unreadable.
    fn read_plist_version(plist_path: &Path) -> Option<String> {
        let value = crate::read_plist(plist_path)?;
        let dict = value.as_dictionary()?;
        dict.get("CFBundleShortVersionString")
            .or_else(|| dict.get("CFBundleVersion"))
            .and_then(|v| v.as_string())
            .map(str::to_owned)
    }

    /// Compare dotted-numeric version strings component-by-component as integers
    /// (`148.0.7778.216` vs `148.0.7778.179`). Used only to pick the newest
    /// version directory, so non-numeric components simply count as 0.
    fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
        use std::cmp::Ordering::Equal;
        let mut ai = a.split('.');
        let mut bi = b.split('.');
        loop {
            match (ai.next(), bi.next()) {
                (None, None) => return Equal,
                (x, y) => {
                    let xv: u64 = x.unwrap_or("0").parse().unwrap_or(0);
                    let yv: u64 = y.unwrap_or("0").parse().unwrap_or(0);
                    match xv.cmp(&yv) {
                        Equal => continue,
                        o => return o,
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cmp_picks_newer_chrome_build() {
            assert!(cmp_version("148.0.7778.216", "148.0.7778.179").is_gt());
            // Numeric, not lexicographic: 100 > 99.
            assert!(cmp_version("148.0.7778.100", "148.0.7778.99").is_gt());
            assert!(cmp_version("148.0.7778.216", "148.0.7778.216").is_eq());
        }
    }
}
