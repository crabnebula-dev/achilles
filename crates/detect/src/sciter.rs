//! Sciter probe.
//!
//! Sciter can be embedded as either:
//!
//! 1. A framework at `Contents/Frameworks/Sciter.framework/` with a version
//!    in its Info.plist, or
//! 2. A shared dylib at `Contents/Frameworks/libsciter.dylib` (or similar),
//!    in which case the version lives as a string inside the binary, e.g.
//!    `Sciter 6.0.0.12`.
//!
//! Both paths populate the same return.

use std::path::Path;
use std::sync::LazyLock;

use memmap2::Mmap;
use regex::bytes::Regex;

/// Matches a Sciter self-identification string seen in shipped builds:
/// `Sciter 6.0.0.12` / `Sciter 5.0.0.7`, etc.
static SCITER_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Sciter (\d+\.\d+\.\d+(?:\.\d+)?)").unwrap());

pub fn detect(app_path: &Path) -> Result<Option<String>, crate::DetectError> {
    // Framework flavour — preferred because it's deterministic.
    let fw = app_path.join("Contents/Frameworks/Sciter.framework");
    if fw.is_dir() {
        for rel in &[
            "Versions/A/Resources/Info.plist",
            "Resources/Info.plist",
        ] {
            let plist = fw.join(rel);
            if plist.exists() {
                if let Some(v) = read_plist_version(&plist) {
                    return Ok(Some(v));
                }
            }
        }
        return Ok(Some("unknown".to_string()));
    }

    // Dylib flavour — scan every `libsciter*.dylib` we find under Frameworks.
    let frameworks = app_path.join("Contents/Frameworks");
    if let Ok(entries) = std::fs::read_dir(&frameworks) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if !name_s.starts_with("libsciter") || !name_s.ends_with(".dylib") {
                continue;
            }
            let path = entry.path();
            match scan_dylib(&path) {
                Ok(Some(v)) => return Ok(Some(v)),
                Ok(None) => return Ok(Some("unknown".to_string())),
                Err(err) => return Err(err),
            }
        }
    }

    Ok(None)
}

fn read_plist_version(plist_path: &Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}

fn scan_dylib(path: &Path) -> Result<Option<String>, crate::DetectError> {
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
