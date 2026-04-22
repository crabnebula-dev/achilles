//! Tauri detection.
//!
//! Tauri apps statically link the Tauri runtime into the main Mach-O binary,
//! so there's no "framework bundle" to look at the way Electron has. Instead
//! we string-scan the main executable for three independent fingerprints and
//! vote:
//!
//! 1. A cargo-registry debug path referencing a `tauri-*` crate with a
//!    semver tag. This also gives us the crate version.
//! 2. `tauri.localhost` — Tauri's internal IPC host, baked in as a literal.
//! 3. `__TAURI_INTERNALS__` (Tauri 2) or `__TAURI__` (Tauri 1) — the JS-side
//!    globals, which appear as literal strings in the binary because the
//!    Rust side emits them into injected scripts.
//!
//! Any single one of these can false-positive or false-negative on its own
//! (stripped symbols kill signal 1; some non-Tauri apps may embed one of
//! the strings as documentation). Two or more signals → High confidence.

use std::path::Path;

use crate::{bundle::BundleInfo, strings, Confidence, Versions};

pub struct Detection {
    pub confidence: Confidence,
    pub versions: Versions,
}

pub fn detect(bundle: &BundleInfo) -> Result<Option<Detection>, crate::DetectError> {
    let Some(exe) = bundle.executable.as_deref() else {
        return Ok(None);
    };
    if !exe.exists() {
        return Ok(None);
    }

    let tauri_version = strings::scan_tauri_version(exe).map_err(io_err(exe))?;
    let has_localhost = strings::contains(exe, b"tauri.localhost").map_err(io_err(exe))?;
    let has_internals = strings::contains(exe, b"__TAURI_INTERNALS__").map_err(io_err(exe))?
        || strings::contains(exe, b"__TAURI__").map_err(io_err(exe))?;

    let signals = [tauri_version.is_some(), has_localhost, has_internals]
        .into_iter()
        .filter(|&x| x)
        .count();

    if signals == 0 {
        return Ok(None);
    }

    // Two or more independent signals → High. One signal is Medium if it's
    // the version path (distinctive) and Low if it's just a string literal
    // that happens to appear.
    let confidence = if signals >= 2 {
        Confidence::High
    } else if tauri_version.is_some() {
        Confidence::Medium
    } else {
        Confidence::Low
    };

    Ok(Some(Detection {
        confidence,
        versions: Versions {
            tauri: tauri_version,
            ..Versions::default()
        },
    }))
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> crate::DetectError + '_ {
    move |source| crate::DetectError::Io {
        path: path.to_path_buf(),
        source,
    }
}
