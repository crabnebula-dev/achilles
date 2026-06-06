//! The system webview engine that WKWebView-style apps (Tauri, Wails) render
//! with. This isn't a per-app bundled runtime — it tracks with the OS — but
//! it's the effective engine version those apps use, so we surface it per row.
//!
//! * macOS: WKWebView ≈ the installed Safari version (`apple:safari` CVEs).
//! * Windows: the Evergreen **WebView2** runtime (Chromium-based → Chromium
//!   CVEs).
//! * Linux: **WebKitGTK** (`libwebkit2gtk-4.x`), WebKit-based.

use std::sync::OnceLock;

use crate::Versions;

/// The system webview engine and its version.
pub enum SystemWebview {
    /// WebKit-based (macOS WKWebView, Linux WebKitGTK). Maps to
    /// [`Versions::webkit`].
    Webkit(String),
    /// Chromium-based (Windows WebView2 / Edge). Maps to
    /// [`Versions::chromium`].
    Chromium(String),
}

static CACHED: OnceLock<Option<SystemWebviewCache>> = OnceLock::new();

// `SystemWebview` isn't `Clone`; cache a cloneable shadow.
#[derive(Clone)]
#[allow(dead_code)] // variants are platform-specific (Chromium = Windows only)
enum SystemWebviewCache {
    Webkit(String),
    Chromium(String),
}

/// Detect the system webview engine version, memoised for the process.
pub fn detect() -> Option<SystemWebview> {
    CACHED.get_or_init(probe).clone().map(|c| match c {
        SystemWebviewCache::Webkit(v) => SystemWebview::Webkit(v),
        SystemWebviewCache::Chromium(v) => SystemWebview::Chromium(v),
    })
}

/// Fold the system-webview version into `versions`: WebKit overwrites
/// `webkit`; Chromium fills `chromium` only if a per-app value wasn't found.
pub fn apply(webview: Option<&SystemWebview>, versions: &mut Versions) {
    match webview {
        Some(SystemWebview::Webkit(v)) => versions.webkit = Some(v.clone()),
        Some(SystemWebview::Chromium(v)) => {
            if versions.chromium.is_none() {
                versions.chromium = Some(v.clone());
            }
        }
        None => {}
    }
}

fn probe() -> Option<SystemWebviewCache> {
    #[cfg(target_os = "macos")]
    {
        crate::safari::system_webkit_version().map(SystemWebviewCache::Webkit)
    }
    #[cfg(target_os = "windows")]
    {
        windows::webview2_version().map(SystemWebviewCache::Chromium)
    }
    #[cfg(target_os = "linux")]
    {
        linux::webkitgtk_version().map(SystemWebviewCache::Webkit)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use winreg::enums::*;
    use winreg::RegKey;

    // Evergreen WebView2 runtime registers its version under this client GUID.
    const CLIENT: &str = r"Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

    pub fn webview2_version() -> Option<String> {
        // Per-machine (x64 installs land under WOW6432Node) then per-user.
        for (hive, sub) in [
            (
                HKEY_LOCAL_MACHINE,
                format!(r"SOFTWARE\WOW6432Node\{CLIENT}"),
            ),
            (HKEY_LOCAL_MACHINE, format!(r"SOFTWARE\{CLIENT}")),
            (HKEY_CURRENT_USER, format!(r"SOFTWARE\{CLIENT}")),
        ] {
            if let Ok(key) = RegKey::predef(hive).open_subkey(&sub) {
                if let Ok(v) = key.get_value::<String, _>("pv") {
                    if !v.is_empty() && v != "0.0.0.0" {
                        return Some(v);
                    }
                }
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;

    /// Resolve the WebKitGTK version from the installed
    /// `libwebkit2gtk-4.x.so.X.Y.Z` soname. We can't read the API/library
    /// version of WebKit itself without dlopen, but the so-version is a usable
    /// proxy for cross-referencing advisories.
    pub fn webkitgtk_version() -> Option<String> {
        let dirs = [
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/lib",
        ];
        for dir in dirs {
            if let Some(v) = scan_dir(Path::new(dir)) {
                return Some(v);
            }
        }
        None
    }

    fn scan_dir(dir: &Path) -> Option<String> {
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // e.g. libwebkit2gtk-4.1.so.0.13.4 / libwebkitgtk-6.0.so.4.6.0
            if (name.starts_with("libwebkit2gtk-") || name.starts_with("libwebkitgtk-"))
                && name.contains(".so.")
            {
                if let Some(v) = name.split(".so.").nth(1) {
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        None
    }
}
