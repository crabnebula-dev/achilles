//! Deno-desktop probe.
//!
//! A Deno-desktop app compiles the user's code together with the Deno runtime
//! into a single executable, driving the OS webview (or a bundled CEF, which we
//! detect separately). There's no bundled framework directory — the signal
//! lives in the main binary.
//!
//! Like Electron's `Chrome/…` and Wails' Go module path, the Deno runtime bakes
//! a stable, distinctive product token into its HTTP client user-agent:
//! `Deno/2.7.5`. We match that literal, which doubles as the presence marker
//! and the version. This maps to `cpe:2.3:a:deno:deno:*` for CVE lookup.
//!
//! NOTE: best-effort — validate against a real `deno desktop` app and widen the
//! marker if some builds don't carry the UA token verbatim.

use std::path::Path;

/// Return the Deno runtime version if the executable is a Deno-desktop binary,
/// else `None`.
pub fn detect(executable: &Path) -> Result<Option<String>, crate::DetectError> {
    if !executable.exists() {
        return Ok(None);
    }
    crate::strings::scan_deno_version(executable).map_err(|e| crate::DetectError::Io {
        path: executable.to_path_buf(),
        source: e,
    })
}
