//! React Native probe.
//!
//! RN apps ship a JS engine — usually **Hermes** — plus recognisable RN
//! symbols in the main binary.
//!
//! * **macOS**: `Contents/Frameworks/hermes.framework` (strong signal, version
//!   in its Info.plist), else a string-scan fallback (`RCTBridge`,
//!   `facebook::react`).
//! * **Windows**: `hermes.dll` / `Microsoft.ReactNative.dll`.
//! * **Linux**: `libhermes.so` (or RN symbols in the binary).
//!
//! A bundled engine is the high-confidence signal; the string-scan fallback is
//! medium. `bundled_engine` records which fired so the caller can rate it.

use crate::app::Layout;
use crate::strings;

pub struct Detection {
    pub version: Option<String>,
    /// True when a bundled JS engine (Hermes framework / library) was found,
    /// vs. only the binary-string fallback.
    pub bundled_engine: bool,
}

pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
    #[cfg(macos_layout)]
    {
        let hermes_dir = layout.frameworks_dir().join("hermes.framework");
        if vfs::is_dir(&hermes_dir) {
            let version = read_hermes_version(&hermes_dir).or(Some("unknown".to_string()));
            return Ok(Some(Detection {
                version,
                bundled_engine: true,
            }));
        }
    }

    #[cfg(not(macos_layout))]
    {
        if layout.has_library("hermes") || layout.has_library("reactnative") {
            return Ok(Some(Detection {
                version: Some("unknown".to_string()),
                bundled_engine: true,
            }));
        }
    }

    // Engine not bundled separately — fall back to string-scanning the main
    // executable for RN-specific symbols.
    if let Some(exe) = layout.executable.as_deref() {
        if vfs::exists(exe)
            && (strings::contains(exe, b"facebook::react").unwrap_or(false)
                || strings::contains(exe, b"RCTBridge").unwrap_or(false)
                || strings::contains(exe, b"RCTRootView").unwrap_or(false))
        {
            return Ok(Some(Detection {
                version: Some("unknown".to_string()),
                bundled_engine: false,
            }));
        }
    }

    Ok(None)
}

#[cfg(macos_layout)]
fn read_hermes_version(framework_dir: &std::path::Path) -> Option<String> {
    for rel in &["Versions/A/Resources/Info.plist", "Resources/Info.plist"] {
        let plist = framework_dir.join(rel);
        if !vfs::exists(&plist) {
            continue;
        }
        let value = crate::read_plist(&plist)?;
        let dict = value.as_dictionary()?;
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
