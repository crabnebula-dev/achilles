//! Wails probe.
//!
//! Wails is Go + system WKWebView. There's no bundled framework — every
//! signal lives in the main Mach-O binary. Go embeds build-info for every
//! linked module, so the Wails version appears as a literal string like
//! `github.com/wailsapp/wails/v2@v2.9.2` (or `/v3@…`). We match that
//! pattern and extract the semver.

use std::path::Path;
use std::sync::LazyLock;

use memmap2::Mmap;
use regex::bytes::Regex;

/// Captures the Wails crate version from its Go module path, e.g.
/// `github.com/wailsapp/wails/v2@v2.9.2`.
static WAILS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"github\.com/wailsapp/wails(?:/v\d+)?@v(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)").unwrap()
});

pub fn detect(executable: &Path) -> Result<Option<String>, crate::DetectError> {
    if !executable.exists() {
        return Ok(None);
    }
    let file = match std::fs::File::open(executable) {
        Ok(f) => f,
        Err(e) => {
            return Err(crate::DetectError::Io {
                path: executable.to_path_buf(),
                source: e,
            })
        }
    };
    // Safety: read-only mapping, never aliased as `&mut`.
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| crate::DetectError::Io {
        path: executable.to_path_buf(),
        source: e,
    })?;

    if let Some(caps) = WAILS_RE.captures(&mmap) {
        if let Some(m) = caps.get(1) {
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                return Ok(Some(s.to_owned()));
            }
        }
    }
    Ok(None)
}
