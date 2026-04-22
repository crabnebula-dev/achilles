//! Electron detection.
//!
//! An Electron app ships with `Contents/Frameworks/Electron Framework.framework`.
//! That directory's presence is our High-confidence positive; the framework's
//! own Info.plist gives us the Electron version; string-scanning its Mach-O
//! yields the bundled Chromium and Node.js versions.
//!
//! Two framework layouts exist in the wild:
//!
//! * **Versioned** (most modern Electron apps): `Versions/A/Electron Framework`
//!   + `Versions/A/Resources/Info.plist`.
//! * **Flat** (e.g. Signal): `Electron Framework` + `Resources/Info.plist`
//!   directly under the framework root.
//!
//! We probe versioned first, fall back to flat.

use std::path::{Path, PathBuf};

use crate::{strings, Confidence, Versions};

pub struct Detection {
    pub confidence: Confidence,
    pub versions: Versions,
}

const FRAMEWORK_REL: &str = "Contents/Frameworks/Electron Framework.framework";
const FRAMEWORK_BIN_NAME: &str = "Electron Framework";

/// Candidate (plist, binary) relative paths within the framework dir, ordered
/// by preference.
const LAYOUT_CANDIDATES: &[(&str, &str)] = &[
    ("Versions/A/Resources/Info.plist", "Versions/A/Electron Framework"),
    ("Resources/Info.plist", FRAMEWORK_BIN_NAME),
];

pub fn detect(app_path: &Path) -> Result<Option<Detection>, crate::DetectError> {
    let framework_dir = app_path.join(FRAMEWORK_REL);
    if !framework_dir.is_dir() {
        return Ok(None);
    }

    let (plist_path, framework_bin) = resolve_layout(&framework_dir);

    let electron = plist_path
        .as_deref()
        .and_then(read_framework_version);

    let (chromium, node) = match framework_bin.as_deref() {
        Some(bin) => strings::scan_electron_versions(bin).map_err(|source| {
            crate::DetectError::Io {
                path: bin.to_path_buf(),
                source,
            }
        })?,
        None => (None, None),
    };

    let confidence = match (electron.is_some(), chromium.is_some()) {
        (true, true) => Confidence::High,
        (true, false) | (false, true) => Confidence::Medium,
        // Framework dir exists but neither version fingerprint matched —
        // the framework binary is probably stripped or heavily modified.
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

/// Pick the first (plist, binary) pair whose files both exist. If no layout
/// matches cleanly, return whatever partial result we can so callers still
/// report the bundle as Electron (at Low confidence).
fn resolve_layout(framework_dir: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    for (plist_rel, bin_rel) in LAYOUT_CANDIDATES {
        let plist = framework_dir.join(plist_rel);
        let bin = framework_dir.join(bin_rel);
        if plist.exists() && bin.exists() {
            return (Some(plist), Some(bin));
        }
    }
    // Partial fallback: surface whichever exists so we still pick up at least
    // one signal.
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
