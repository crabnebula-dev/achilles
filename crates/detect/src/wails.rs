//! Wails probe.
//!
//! Wails is Go + system WKWebView. There's no bundled framework — every
//! signal lives in the main Mach-O binary. Go embeds build-info for every
//! linked module, so the Wails version appears as a literal string like
//! `github.com/wailsapp/wails/v2@v2.9.2` (or `/v3@…`). We match that
//! pattern and extract the semver.

use std::path::Path;
use std::sync::LazyLock;

use regex::bytes::Regex;

/// Captures the Wails crate version from its Go module path, e.g.
/// `github.com/wailsapp/wails/v2@v2.9.2`.
static WAILS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"github\.com/wailsapp/wails(?:/v\d+)?@v(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)").unwrap()
});

pub fn detect(executable: &Path) -> Result<Option<String>, crate::DetectError> {
    if !vfs::exists(executable) {
        return Ok(None);
    }
    let bytes = crate::strings::map_bytes(executable).map_err(|source| crate::DetectError::Io {
        path: executable.to_path_buf(),
        source,
    })?;

    if let Some(caps) = WAILS_RE.captures(&bytes) {
        if let Some(m) = caps.get(1) {
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                return Ok(Some(s.to_owned()));
            }
        }
    }
    Ok(None)
}
