//! Sciter probe.
//!
//! Sciter is an embeddable HTML/CSS UI engine shipped as a shared library (or,
//! on macOS, a framework). Its self-identification string — `Sciter 6.0.0.12`
//! — is baked into the binary, so the version extracts the same way wherever
//! the library lives.
//!
//! * **macOS**: `Contents/Frameworks/Sciter.framework` or `libsciter*.dylib`.
//! * **Windows**: `sciter.dll`.
//! * **Linux**: `libsciter-gtk.so` / `libsciter.so`.

use std::path::Path;
use std::sync::LazyLock;

use memmap2::Mmap;
use regex::bytes::Regex;

use crate::app::Layout;

/// Matches a Sciter self-identification string seen in shipped builds:
/// `Sciter 6.0.0.12` / `Sciter 5.0.0.7`, etc.
static SCITER_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Sciter (\d+\.\d+\.\d+(?:\.\d+)?)").unwrap());

pub fn detect(layout: &Layout) -> Result<Option<String>, crate::DetectError> {
    #[cfg(target_os = "macos")]
    {
        // Framework flavour — preferred because it's deterministic.
        let fw = layout.frameworks_dir().join("Sciter.framework");
        if fw.is_dir() {
            for rel in &["Versions/A/Resources/Info.plist", "Resources/Info.plist"] {
                let plist = fw.join(rel);
                if plist.exists() {
                    if let Some(v) = read_plist_version(&plist) {
                        return Ok(Some(v));
                    }
                }
            }
            return Ok(Some("unknown".to_string()));
        }
    }

    // Shared-library flavour (every platform): find a sciter library and scan
    // it for the version string.
    if let Some(path) = layout.find_file("sciter") {
        if is_sciter_library(&path) {
            return match scan_library(&path) {
                Ok(Some(v)) => Ok(Some(v)),
                Ok(None) => Ok(Some("unknown".to_string())),
                Err(err) => Err(err),
            };
        }
    }

    Ok(None)
}

/// Guard against matching unrelated files that merely contain "sciter" in a
/// longer name — accept only actual shared-library extensions.
fn is_sciter_library(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.ends_with(".dll") || name.contains(".so") || name.ends_with(".dylib")
}

#[cfg(target_os = "macos")]
fn read_plist_version(plist_path: &Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}

fn scan_library(path: &Path) -> Result<Option<String>, crate::DetectError> {
    let file = std::fs::File::open(path).map_err(|e| crate::DetectError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| crate::DetectError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if let Some(caps) = SCITER_VERSION_RE.captures(&mmap) {
        if let Some(m) = caps.get(1) {
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                return Ok(Some(s.to_owned()));
            }
        }
    }
    Ok(None)
}
