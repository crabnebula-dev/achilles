//! Qt probe.
//!
//! * **macOS**: `Qt*.framework` bundles under `Contents/Frameworks/`.
//!   `QtCore.framework` pins the Qt version (its Info.plist); a
//!   `QtWebEngineCore.framework` means Qt embeds Chromium, which we
//!   string-scan for the `Chrome/<version>` UA marker.
//! * **Windows**: `Qt{5,6}Core.dll` (+ `Qt{5,6}WebEngineCore.dll`).
//! * **Linux**: `libQt{5,6}Core.so*` (+ `libQt{5,6}WebEngineCore.so*`), bundled
//!   or imported by the binary.
//!
//! Off macOS the Qt version is read by string-scanning the Qt core library for
//! a `Qt x.y.z` marker, falling back to `"unknown"`.

use crate::app::Layout;
use crate::strings;

pub struct Detection {
    pub qt_version: Option<String>,
    pub chromium_version: Option<String>,
}

pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
    #[cfg(macos_layout)]
    {
        macos::detect(layout)
    }
    #[cfg(not(macos_layout))]
    {
        portable::detect(layout)
    }
}

#[cfg(not(macos_layout))]
mod portable {
    use super::*;
    use std::sync::LazyLock;

    use regex::bytes::Regex;

    static QT_VERSION_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"Qt (\d+\.\d+\.\d+)").unwrap());

    pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
        if !(layout.has_library("qt5core") || layout.has_library("qt6core")) {
            return Ok(None);
        }

        let qt_version = layout
            .find_file("qt5core")
            .or_else(|| layout.find_file("qt6core"))
            .and_then(|lib| scan_qt_version(&lib));

        // QtWebEngine bundles a Chromium content shell.
        let chromium_version = layout
            .find_file("qt5webenginecore")
            .or_else(|| layout.find_file("qt6webenginecore"))
            .and_then(|bin| strings::scan_electron_versions(&bin).ok())
            .and_then(|(chromium, _)| chromium);

        Ok(Some(Detection {
            qt_version,
            chromium_version,
        }))
    }

    fn scan_qt_version(lib: &std::path::Path) -> Option<String> {
        let data = std::fs::read(lib).ok()?;
        QT_VERSION_RE
            .captures(&data)
            .and_then(|c| c.get(1))
            .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
            .map(str::to_owned)
    }
}

#[cfg(macos_layout)]
mod macos {
    use std::path::Path;

    use super::*;

    pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
        let frameworks = layout.frameworks_dir();
        let qt_core_dir = frameworks.join("QtCore.framework");
        if !vfs::is_dir(&qt_core_dir) {
            return Ok(None);
        }

        let qt_version = read_qt_core_version(&qt_core_dir);
        let chromium_version = scan_qt_webengine_chromium(&frameworks)?;

        Ok(Some(Detection {
            qt_version,
            chromium_version,
        }))
    }

    fn read_qt_core_version(qt_core_dir: &Path) -> Option<String> {
        for rel in &[
            "Versions/A/Resources/Info.plist",
            "Versions/5/Resources/Info.plist",
            "Versions/6/Resources/Info.plist",
            "Resources/Info.plist",
        ] {
            let plist = qt_core_dir.join(rel);
            if !vfs::exists(&plist) {
                continue;
            }
            if let Some(v) = plist_version(&plist) {
                return Some(v);
            }
        }
        None
    }

    fn scan_qt_webengine_chromium(frameworks: &Path) -> Result<Option<String>, crate::DetectError> {
        let qt_webengine_dir = frameworks.join("QtWebEngineCore.framework");
        if !vfs::is_dir(&qt_webengine_dir) {
            return Ok(None);
        }
        for rel in &[
            "Versions/A/QtWebEngineCore",
            "Versions/5/QtWebEngineCore",
            "Versions/6/QtWebEngineCore",
            "QtWebEngineCore",
        ] {
            let bin = qt_webengine_dir.join(rel);
            if vfs::exists(&bin) {
                let (chromium, _node) =
                    strings::scan_electron_versions(&bin).map_err(|source| {
                        crate::DetectError::Io {
                            path: bin.clone(),
                            source,
                        }
                    })?;
                return Ok(chromium);
            }
        }
        Ok(None)
    }

    fn plist_version(plist_path: &Path) -> Option<String> {
        let value = crate::read_plist(plist_path)?;
        let dict = value.as_dictionary()?;
        dict.get("CFBundleShortVersionString")
            .or_else(|| dict.get("CFBundleVersion"))
            .and_then(|v| v.as_string())
            .map(str::to_owned)
    }
}
