//! Low-level byte scanning of executables for version fingerprints.
//!
//! We mmap each binary and run a handful of pre-compiled patterns across it.
//! Nothing here parses object-file headers — we rely on the fact that the
//! strings we look for (`Chrome/x.y.z`, `node-vX.Y.Z`, `Electron/x.y.z`,
//! `tauri.localhost`, `/tauri-N.M.P/`) are stable, distinctive, and appear
//! verbatim in the binary's string data. Because we scan raw bytes rather than
//! a particular section format, this works identically on Mach-O, PE, and ELF.

use std::path::Path;
use std::sync::LazyLock;

#[cfg(not(target_arch = "wasm32"))]
use memmap2::Mmap;
use regex::bytes::Regex;

/// Captures the Chromium version embedded in the UA string literal that
/// Electron bakes into its framework binary: `Chrome/144.0.7559.173`.
static CHROMIUM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Chrome/(\d+\.\d+\.\d+\.\d+)").unwrap());

/// Captures the Node.js version from the tarball-URL string Electron embeds:
/// `https://nodejs.org/download/release/v24.13.0/node-v24.13.0.tar.gz`.
static NODE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"node-v(\d+\.\d+\.\d+)").unwrap());

/// Captures the *bare* Tauri crate version from cargo-registry debug paths
/// that Rust leaves in release binaries (panic locations, etc.).
///
/// We deliberately match only `/tauri-X.Y.Z/` — not `/tauri-plugin-*-X.Y.Z/`
/// or `/tauri-runtime-*-X.Y.Z/` — because Tauri plugins have their own
/// independent versions, and picking up e.g. `tauri-plugin-store-2.4.2`
/// would mislabel an app's Tauri core version.
static TAURI_CRATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/tauri-(\d+\.\d+\.\d+)(?:-[a-zA-Z0-9.]+)?/").unwrap());

/// Captures the Electron version Electron bakes into its default user-agent
/// product token: `Electron/40.4.1`. This is the cross-platform substitute for
/// reading the framework Info.plist (which only exists on macOS).
#[allow(dead_code)] // used by the non-macOS Electron probe
static ELECTRON_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Electron/(\d+\.\d+\.\d+)").unwrap());

/// Scan an Electron framework binary for Chromium and Node.js versions.
pub fn scan_electron_versions(
    binary_path: &Path,
) -> std::io::Result<(Option<String>, Option<String>)> {
    let mmap = map_bytes(binary_path)?;
    Ok((find_first(&CHROMIUM_RE, &mmap), find_first(&NODE_RE, &mmap)))
}

/// Scan a binary for the Electron version embedded in its user-agent string.
#[allow(dead_code)] // used by the non-macOS Electron probe
pub fn scan_electron_version(binary_path: &Path) -> std::io::Result<Option<String>> {
    let mmap = map_bytes(binary_path)?;
    Ok(find_first(&ELECTRON_RE, &mmap))
}

/// Captures the Deno runtime version from the `Deno/<version>` product token
/// Deno bakes into its HTTP client's user-agent string. Like `Chrome/` and
/// `Electron/`, this literal is stable and distinctive, so it serves as both
/// the presence marker and the version for a Deno-desktop binary.
static DENO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Deno/(\d+\.\d+\.\d+)").unwrap());

/// Scan a Tauri main binary for the Tauri crate version.
pub fn scan_tauri_version(binary_path: &Path) -> std::io::Result<Option<String>> {
    let mmap = map_bytes(binary_path)?;
    Ok(find_first(&TAURI_CRATE_RE, &mmap))
}

/// Scan a binary for the Deno runtime version in its `Deno/x.y.z` UA token.
pub fn scan_deno_version(binary_path: &Path) -> std::io::Result<Option<String>> {
    let mmap = open_mmap(binary_path)?;
    Ok(find_first(&DENO_RE, &mmap))
}

/// Cheap substring check against a mmap'd file.
pub fn contains(binary_path: &Path, needle: &[u8]) -> std::io::Result<bool> {
    let mmap = map_bytes(binary_path)?;
    Ok(memchr::memmem::find(&mmap, needle).is_some())
}

/// Get the bytes of a binary to scan: a read-only mmap on native, an owned
/// buffer (from the in-memory upload tree) on wasm. Both deref to `[u8]`, so
/// every scanner below is identical across targets. Shared with the `sciter`
/// and `wails` probes.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn map_bytes(
    binary_path: &Path,
) -> std::io::Result<impl std::ops::Deref<Target = [u8]>> {
    let file = std::fs::File::open(binary_path)?;
    // Safety: we only read the mapping and never alias it as `&mut`. If the
    // underlying file is modified mid-scan the worst outcome is a skewed
    // version string, which is no worse than racing with any other scanner.
    unsafe { Mmap::map(&file) }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn map_bytes(
    binary_path: &Path,
) -> std::io::Result<impl std::ops::Deref<Target = [u8]>> {
    vfs::read(binary_path)
}

fn find_first(re: &Regex, haystack: &[u8]) -> Option<String> {
    re.captures(haystack)
        .and_then(|c| c.get(1))
        .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deno_ua_token_yields_version() {
        // `scan_deno_version` keys on the `Deno/x.y.z` product token the runtime
        // bakes into its HTTP user-agent.
        let hay = b"Mozilla/5.0 (compatible) Deno/2.7.5 trailing";
        assert_eq!(find_first(&DENO_RE, hay), Some("2.7.5".to_string()));
        assert_eq!(find_first(&DENO_RE, b"nothing deno-ish here"), None);
    }
}
