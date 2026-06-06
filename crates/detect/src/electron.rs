//! Electron detection.
//!
//! The on-disk shape differs per platform, but the version fingerprints all
//! live as literal strings in the main binary, so they extract identically.
//!
//! * **macOS**: `Contents/Frameworks/Electron Framework.framework` — its
//!   Info.plist carries the Electron version; string-scanning its Mach-O
//!   yields Chromium and Node.js. Two layouts exist: *versioned*
//!   (`Versions/A/...`) and *flat* (Signal).
//! * **Windows / Linux**: no framework bundle. The signal is a
//!   `resources/{app,electron}.asar` archive next to Chromium support files
//!   (`*.pak`, `icudtl.dat`); the Electron / Chromium / Node versions come
//!   from string-scanning the main executable.

use crate::app::Layout;
use crate::{strings, Confidence, Versions};

pub struct Detection {
    pub confidence: Confidence,
    pub versions: Versions,
}

pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
    #[cfg(target_os = "macos")]
    {
        macos::detect(layout)
    }
    #[cfg(not(target_os = "macos"))]
    {
        portable::detect(layout)
    }
}

#[cfg(not(target_os = "macos"))]
mod portable {
    use super::*;

    pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
        // An `.asar` is Electron-specific. The `resources/app` unpacked layout
        // (VS Code) and a top-level `node_modules.asar` are equally telling.
        let resources = layout.resources_dir();
        let has_asar = ["app.asar", "electron.asar", "default_app.asar"]
            .iter()
            .any(|f| resources.join(f).is_file())
            || resources.join("app").join("package.json").is_file()
            || layout.root.join("node_modules.asar").is_file();

        let (electron, chromium, node) = match layout.executable.as_deref() {
            Some(exe) if exe.exists() => {
                let electron = strings::scan_electron_version(exe).map_err(io_err(exe))?;
                let (chromium, node) = strings::scan_electron_versions(exe).map_err(io_err(exe))?;
                (electron, chromium, node)
            }
            _ => (None, None, None),
        };

        // The `Electron/<v>` user-agent token (and the bundled `node-v` URL)
        // distinguish Electron from a plain Chromium browser, which has neither.
        let is_electron = has_asar || electron.is_some() || node.is_some();
        if !is_electron {
            return Ok(None);
        }

        let confidence = match (electron.is_some(), chromium.is_some()) {
            (true, true) => Confidence::High,
            (true, false) | (false, true) => Confidence::Medium,
            // Only the `.asar` matched (stripped binary) — still Electron.
            (false, false) => Confidence::Low,
        };

        Ok(Some(Detection {
            confidence,
            versions: Versions {
                electron,
                chromium,
                node,
                ..Versions::default()
            },
        }))
    }

    fn io_err(path: &std::path::Path) -> impl Fn(std::io::Error) -> crate::DetectError + '_ {
        move |source| crate::DetectError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::{Path, PathBuf};

    use super::*;

    const FRAMEWORK: &str = "Electron Framework.framework";
    const FRAMEWORK_BIN_NAME: &str = "Electron Framework";

    /// Candidate (plist, binary) relative paths within the framework dir,
    /// ordered by preference.
    const LAYOUT_CANDIDATES: &[(&str, &str)] = &[
        (
            "Versions/A/Resources/Info.plist",
            "Versions/A/Electron Framework",
        ),
        ("Resources/Info.plist", FRAMEWORK_BIN_NAME),
    ];

    pub fn detect(layout: &Layout) -> Result<Option<Detection>, crate::DetectError> {
        let framework_dir = layout.frameworks_dir().join(FRAMEWORK);
        if !framework_dir.is_dir() {
            return Ok(None);
        }

        let (plist_path, framework_bin) = resolve_layout(&framework_dir);

        let electron = plist_path.as_deref().and_then(read_framework_version);

        let (chromium, node) = match framework_bin.as_deref() {
            Some(bin) => {
                strings::scan_electron_versions(bin).map_err(|source| crate::DetectError::Io {
                    path: bin.to_path_buf(),
                    source,
                })?
            }
            None => (None, None),
        };

        let confidence = match (electron.is_some(), chromium.is_some()) {
            (true, true) => Confidence::High,
            (true, false) | (false, true) => Confidence::Medium,
            (false, false) => Confidence::Low,
        };

        Ok(Some(Detection {
            confidence,
            versions: Versions {
                electron,
                chromium,
                node,
                ..Versions::default()
            },
        }))
    }

    fn resolve_layout(framework_dir: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
        for (plist_rel, bin_rel) in LAYOUT_CANDIDATES {
            let plist = framework_dir.join(plist_rel);
            let bin = framework_dir.join(bin_rel);
            if plist.exists() && bin.exists() {
                return (Some(plist), Some(bin));
            }
        }
        let plist = LAYOUT_CANDIDATES
            .iter()
            .map(|(p, _)| framework_dir.join(p))
            .find(|p| p.exists());
        let bin = LAYOUT_CANDIDATES
            .iter()
            .map(|(_, b)| framework_dir.join(b))
            .find(|b| b.exists());
        (plist, bin)
    }

    fn read_framework_version(plist_path: &Path) -> Option<String> {
        let value = plist::Value::from_file(plist_path).ok()?;
        let dict = value.as_dictionary()?;
        dict.get("CFBundleVersion")
            .and_then(|v| v.as_string())
            .map(str::to_owned)
    }
}
