//! Native-messaging-host manifest audit.
//!
//! Chromium-based browsers expose extensions-to-native-app communication
//! via per-profile JSON manifests at:
//!
//! ```text
//!   ~/Library/Application Support/<Browser>/NativeMessagingHosts/*.json
//! ```
//!
//! Each manifest names a native executable and a whitelist of extension
//! ids that may speak to it. Apps drop these silently to register a
//! browser bridge. We scan every known browser's directory, parse each
//! manifest, and return the ones whose `path` points back into the app
//! bundle we're analysing.
//!
//! Signal surfaced to the user:
//!   "This app installed a native-messaging host in Chrome/Brave/Edge/…,
//!    letting extensions <id1, id2, …> call into
//!    `<path/to/helper>`."

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One native-messaging-host manifest that references the current bundle.
#[derive(Debug, Clone, Serialize)]
pub struct NativeMessagingHost {
    /// Human-readable browser name (`"Chrome"`, `"Brave"`, …).
    pub browser: String,
    /// Path of the manifest file itself.
    pub manifest_path: PathBuf,
    /// Manifest's declared host name (`name` field, e.g.
    /// `com.anthropic.claude_browser_extension`).
    pub host_name: String,
    /// Path to the native executable the browser will invoke.
    pub target_path: String,
    /// `allowed_origins` — usually `chrome-extension://<id>/` URLs.
    pub allowed_origins: Vec<String>,
    /// Creation time (seconds since epoch), if the OS provides it.
    pub created_at: Option<u64>,
    /// Last-modified time (seconds since epoch).
    pub modified_at: Option<u64>,
}

/// Every Chromium-based browser support directory name we know about.
/// Paths are joined under `~/Library/Application Support/`.
const BROWSER_DIRS: &[(&str, &str)] = &[
    ("Chrome", "Google/Chrome"),
    ("Chrome Beta", "Google/Chrome Beta"),
    ("Chrome Canary", "Google/Chrome Canary"),
    ("Chromium", "Chromium"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Brave Beta", "BraveSoftware/Brave-Browser-Beta"),
    ("Edge", "Microsoft Edge"),
    ("Arc", "Arc"),
    ("Vivaldi", "Vivaldi"),
    ("Opera", "com.operasoftware.Opera"),
    ("Opera GX", "com.operasoftware.OperaGX"),
    ("Firefox", "Firefox"),
];

#[derive(Debug, Deserialize)]
struct ManifestShape {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    allowed_extensions: Vec<String>,
}

/// Scan every known browser's `NativeMessagingHosts/` dir. Return every
/// manifest whose `path` lives under `app_path`.
pub fn scan(app_path: &Path) -> Vec<NativeMessagingHost> {
    let Some(home) = dirs_home() else {
        return Vec::new();
    };
    let support = home.join("Library/Application Support");
    let app_str = app_path.to_string_lossy().into_owned();

    let mut out = Vec::new();
    for (display_name, rel) in BROWSER_DIRS {
        let dir = support.join(rel).join("NativeMessagingHosts");
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(manifest): Result<ManifestShape, _> = serde_json::from_slice(&bytes) else {
                continue;
            };
            let Some(target) = manifest.path.as_deref() else {
                continue;
            };
            // Only keep manifests that point *into* this app's bundle.
            if !target.starts_with(&app_str) {
                continue;
            }

            let (created_at, modified_at) = read_timestamps(&path);
            // Merge `allowed_origins` + `allowed_extensions` so Firefox's
            // different schema doesn't silently vanish.
            let mut origins = manifest.allowed_origins.clone();
            origins.extend(manifest.allowed_extensions);

            out.push(NativeMessagingHost {
                browser: (*display_name).to_owned(),
                manifest_path: path,
                host_name: manifest.name.unwrap_or_default(),
                target_path: target.to_owned(),
                allowed_origins: origins,
                created_at,
                modified_at,
            });
        }
    }

    out
}

fn read_timestamps(path: &Path) -> (Option<u64>, Option<u64>) {
    let Ok(meta) = fs::metadata(path) else {
        return (None, None);
    };
    let created = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    (created, modified)
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
