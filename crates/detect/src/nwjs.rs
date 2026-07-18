//! NW.js probe.
//!
//! * **macOS**: `Contents/Frameworks/nwjs Framework.framework`; the Info.plist
//!   gives the NW.js version and string-scanning the framework binary yields
//!   the embedded Chromium version.
//! * **Windows**: `nw.dll` beside the executable.
//! * **Linux**: `lib/libnw.so` (or the `nw` binary).
//!
//! Off macOS there's no NW.js version string to read, so we report `"unknown"`
//! for it but still recover the Chromium version from the binary.

use crate::app::Layout;
use crate::strings;

pub struct Detection {
    pub nwjs_version: Option<String>,
    pub chromium_version: Option<String>,
}

pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
    #[cfg(macos_layout)]
    {
        macos::detect(layout)
    }
    #[cfg(not(macos_layout))]
    {
        let has_nw = layout.has_library("nw.dll") || layout.find_file("libnw").is_some();
        if !has_nw {
            return Ok(None);
        }
        let chromium_version = layout
            .find_file("nw.dll")
            .or_else(|| layout.find_file("libnw"))
            .or_else(|| layout.executable.clone())
            .and_then(|p| strings::scan_electron_versions(&p).ok())
            .and_then(|(chromium, _)| chromium);
        Ok(Some(Detection {
            nwjs_version: Some("unknown".to_string()),
            chromium_version,
        }))
    }
}

#[cfg(macos_layout)]
mod macos {
    use std::path::Path;

    use super::*;

    const FRAMEWORK_BIN_NAME: &str = "nwjs Framework";

    pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
        let framework_dir = layout.frameworks_dir().join("nwjs Framework.framework");
        if !vfs::is_dir(&framework_dir) {
            return Ok(None);
        }

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
            if vfs::exists(&p) {
                Some((Some(p), vfs::exists(&b).then_some(b)))
            } else {
                None
            }
        })
        .unwrap_or((None, None));

        let nwjs_version = plist.as_deref().and_then(read_version);
        let chromium_version = match bin {
            Some(bin) => {
                strings::scan_electron_versions(&bin)
                    .map_err(|source| crate::DetectError::Io { path: bin, source })?
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
        let value = crate::read_plist(plist_path)?;
        let dict = value.as_dictionary()?;
        dict.get("CFBundleShortVersionString")
            .or_else(|| dict.get("CFBundleVersion"))
            .and_then(|v| v.as_string())
            .map(str::to_owned)
    }
}
