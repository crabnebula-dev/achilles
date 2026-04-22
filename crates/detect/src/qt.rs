//! Qt probe.
//!
//! A Qt-based macOS app ships one or more `Qt*.framework` bundles under
//! `Contents/Frameworks/`. `QtCore.framework` is present in every real Qt
//! app — we use it to pin the Qt runtime version.
//!
//! If the app also bundles `QtWebEngineCore.framework`, Qt is embedding
//! Chromium. We string-scan that binary for the same `Chrome/<version>`
//! user-agent marker Electron emits, so the Chromium version is captured in
//! `Versions::chromium` alongside the primary Qt verdict.

use std::path::Path;

use crate::strings;

const QT_CORE_REL: &str = "Contents/Frameworks/QtCore.framework";
const QT_WEB_ENGINE_CORE_REL: &str = "Contents/Frameworks/QtWebEngineCore.framework";

pub struct Detection {
    pub qt_version: Option<String>,
    pub chromium_version: Option<String>,
}

pub fn detect(app_path: &Path) -> Result<Option<Detection>, crate::DetectError> {
    let qt_core_dir = app_path.join(QT_CORE_REL);
    if !qt_core_dir.is_dir() {
        return Ok(None);
    }

    let qt_version = read_qt_core_version(&qt_core_dir);
    let chromium_version = scan_qt_webengine_chromium(app_path)?;

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
        if !plist.exists() {
            continue;
        }
        if let Some(v) = plist_version(&plist) {
            return Some(v);
        }
    }
    None
}

fn scan_qt_webengine_chromium(
    app_path: &Path,
) -> Result<Option<String>, crate::DetectError> {
    let qt_webengine_dir = app_path.join(QT_WEB_ENGINE_CORE_REL);
    if !qt_webengine_dir.is_dir() {
        return Ok(None);
    }

    // QtWebEngineCore binary location is similar to QtCore.
    for rel in &[
        "Versions/A/QtWebEngineCore",
        "Versions/5/QtWebEngineCore",
        "Versions/6/QtWebEngineCore",
        "QtWebEngineCore",
    ] {
        let bin = qt_webengine_dir.join(rel);
        if bin.exists() {
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
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
