//! Low-level byte scanning of Mach-O binaries for version fingerprints.
//!
//! We mmap each binary and run a handful of pre-compiled patterns across it.
//! Nothing here parses Mach-O headers — we rely on the fact that the strings
//! we look for (`Chrome/x.y.z`, `node-vX.Y.Z`, `tauri.localhost`,
//! `/tauri-N.M.P/`) are stable, distinctive, and appear verbatim in
//! `__TEXT,__cstring` / `__DATA,__const`.

use std::path::Path;
use std::sync::LazyLock;

use memmap2::Mmap;
use regex::bytes::Regex;

/// Captures the Chromium version embedded in the UA string literal that
/// Electron bakes into its framework binary: `Chrome/144.0.7559.173`.
static CHROMIUM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Chrome/(\d+\.\d+\.\d+\.\d+)").unwrap());

/// Captures the Node.js version from the tarball-URL string Electron embeds:
/// `https://nodejs.org/download/release/v24.13.0/node-v24.13.0.tar.gz`.
static NODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"node-v(\d+\.\d+\.\d+)").unwrap());

/// Captures the *bare* Tauri crate version from cargo-registry debug paths
/// that Rust leaves in release binaries (panic locations, etc.).
///
/// We deliberately match only `/tauri-X.Y.Z/` — not `/tauri-plugin-*-X.Y.Z/`
/// or `/tauri-runtime-*-X.Y.Z/` — because Tauri plugins have their own
/// independent versions, and picking up e.g. `tauri-plugin-store-2.4.2`
/// would mislabel an app's Tauri core version.
static TAURI_CRATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/tauri-(\d+\.\d+\.\d+)(?:-[a-zA-Z0-9.]+)?/").unwrap());

/// Scan an Electron framework binary for Chromium and Node.js versions.
pub fn scan_electron_versions(
    binary_path: &Path,
) -> std::io::Result<(Option<String>, Option<String>)> {
    let mmap = open_mmap(binary_path)?;
    Ok((
        find_first(&CHROMIUM_RE, &mmap),
        find_first(&NODE_RE, &mmap),
    ))
}

/// Scan a Tauri main binary for the Tauri crate version.
pub fn scan_tauri_version(binary_path: &Path) -> std::io::Result<Option<String>> {
    let mmap = open_mmap(binary_path)?;
    Ok(find_first(&TAURI_CRATE_RE, &mmap))
}

/// Cheap substring check against a mmap'd file.
pub fn contains(binary_path: &Path, needle: &[u8]) -> std::io::Result<bool> {
    let mmap = open_mmap(binary_path)?;
    Ok(memchr::memmem::find(&mmap, needle).is_some())
}

fn open_mmap(binary_path: &Path) -> std::io::Result<Mmap> {
    let file = std::fs::File::open(binary_path)?;
    // Safety: we only read the mapping and never alias it as `&mut`. If the
    // underlying file is modified mid-scan the worst outcome is a skewed
    // version string, which is no worse than racing with any other scanner.
    unsafe { Mmap::map(&file) }
}

fn find_first(re: &Regex, haystack: &[u8]) -> Option<String> {
    re.captures(haystack)
        .and_then(|c| c.get(1))
        .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
        .map(str::to_owned)
}
