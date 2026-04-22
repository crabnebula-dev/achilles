//! NW.js probe.
//!
//! NW.js apps ship `Contents/Frameworks/nwjs Framework.framework`. Parallel
//! structure to Electron's framework — the Info.plist gives us the NW.js
//! version, and string-scanning the framework binary yields the embedded
//! Chromium version.

use std::path::Path;

use crate::strings;

const FRAMEWORK_REL: &str = "Contents/Frameworks/nwjs Framework.framework";
const FRAMEWORK_BIN_NAME: &str = "nwjs Framework";

pub struct Detection {
    pub nwjs_version: Option<String>,
    pub chromium_version: Option<String>,
}

pub fn detect(app_path: &Path) -> Result<Option<Detection>, crate::DetectError> {
    let framework_dir = app_path.join(FRAMEWORK_REL);
    if !framework_dir.is_dir() {
        return Ok(None);
    }

    // Try versioned layout first, then flat — matches Electron/CEF behaviour.
    let (plist, bin) = [
        ("Versions/A/Resources/Info.plist", "Versions/A"),
        ("Resources/Info.plist", ""),
    ]
    .iter()
    .find_map(|(plist_rel, bin_rel)| {
        let p = framework_dir.join(plist_rel);
        let b = if bin_rel.is_empty() {
            framework_dir.join(FRAMEWORK_BIN_NAME)
        } else {
            framework_dir.join(bin_rel).join(FRAMEWORK_BIN_NAME)
        };
        if p.exists() {
            Some((Some(p), b.exists().then_some(b)))
        } else {
            None
        }
    })
    .unwrap_or((None, None));

    let nwjs_version = plist.as_deref().and_then(read_version);
    let chromium_version = match bin {
        Some(bin) => {
            strings::scan_electron_versions(&bin)
                .map_err(|source| crate::DetectError::Io {
                    path: bin,
                    source,
                })?
                .0
        }
        None => None,
    };

    Ok(Some(Detection {
        nwjs_version,
        chromium_version,
    }))
}

fn read_version(plist_path: &Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
