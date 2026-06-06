//! Detect the system-level side effects an app leaves *outside* its own
//! install location — the things a purely-in-place audit can't see.
//!
//! Each platform has its own conventions, but they map onto the same shape:
//!
//! * **Bundled helpers** — sub-executables shipped alongside the main binary
//!   (macOS `Contents/Helpers|PlugIns|XPCServices`, Windows sibling `.exe`s,
//!   Linux sibling binaries).
//! * **Native-messaging hosts** — browser-bridge manifests the app drops into
//!   browser profiles (macOS `~/Library/Application Support`, Windows registry,
//!   Linux `~/.config`).
//! * **Auto-start / background entries** — launchd agents (macOS), `Run` keys /
//!   Startup folder / scheduled tasks (Windows), autostart `.desktop` /
//!   systemd user units (Linux).
//! * **Log / data directory** — the app's out-of-place state directory.
//!
//! Each can be perfectly legitimate, but apps often install them silently.
//! Surfacing them is a prerequisite for informed user consent.
//!
//! [`analyse`] is the one-shot entry point. All I/O is blocking; run it inside
//! `tokio::task::spawn_blocking`.

use std::path::{Path, PathBuf};

use serde::Serialize;

mod types;
pub use types::{BundleHelper, LaunchEntry, LaunchScope, LogDirectory, NativeMessagingHost};

#[cfg(target_os = "macos")]
mod browsers;
#[cfg(target_os = "macos")]
mod bundle_internal;
#[cfg(target_os = "macos")]
mod launch;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod logs;
#[cfg(target_os = "windows")]
mod windows;

/// Every side-effect we detected for one app.
#[derive(Debug, Clone, Serialize)]
pub struct SideEffects {
    pub app_path: PathBuf,

    /// Helper executables / sub-bundles shipped *inside* the app
    /// (macOS `Contents/Helpers`, sibling `.exe`s / binaries elsewhere).
    pub helpers: Vec<BundleHelper>,
    /// macOS `Contents/PlugIns` (empty on other platforms).
    pub plugins: Vec<BundleHelper>,
    /// macOS `Contents/XPCServices` (empty on other platforms).
    pub xpc_services: Vec<BundleHelper>,

    /// Native-messaging-host manifests, in any browser profile, that point back
    /// into this app.
    pub native_messaging_hosts: Vec<NativeMessagingHost>,

    /// Auto-start / background-launch registrations referencing this app.
    pub launch_entries: Vec<LaunchEntry>,

    /// The app's out-of-place log / data directory, if present.
    pub log_dir: Option<LogDirectory>,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Enumerate every side-effect for the app at `app_path`. `bundle_id` and
/// `executable` are passed explicitly (not re-derived) so callers that already
/// have a `detect::Detection` don't pay for another metadata read.
pub fn analyse(
    app_path: &Path,
    bundle_id: Option<&str>,
    executable: Option<&Path>,
) -> Result<SideEffects, AnalyseError> {
    #[cfg(target_os = "macos")]
    {
        let helpers = bundle_internal::enumerate(app_path, "Contents/Helpers");
        let plugins = bundle_internal::enumerate(app_path, "Contents/PlugIns");
        let xpc_services = bundle_internal::enumerate(app_path, "Contents/XPCServices");
        let native_messaging_hosts = browsers::scan(app_path);
        let launch_entries = launch::scan(app_path, executable);
        let log_dir = logs::find(bundle_id);

        Ok(SideEffects {
            app_path: app_path.to_path_buf(),
            helpers,
            plugins,
            xpc_services,
            native_messaging_hosts,
            launch_entries,
            log_dir,
        })
    }

    #[cfg(target_os = "windows")]
    {
        Ok(windows::analyse(app_path, bundle_id, executable))
    }

    #[cfg(target_os = "linux")]
    {
        Ok(linux::analyse(app_path, bundle_id, executable))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (bundle_id, executable);
        Ok(SideEffects {
            app_path: app_path.to_path_buf(),
            helpers: Vec::new(),
            plugins: Vec::new(),
            xpc_services: Vec::new(),
            native_messaging_hosts: Vec::new(),
            launch_entries: Vec::new(),
            log_dir: None,
        })
    }
}

/// Shared helper: directory size + file count + newest mtime, used by the
/// per-OS log/data-directory probes.
#[cfg(not(target_os = "macos"))]
pub(crate) fn dir_stats(dir: &Path) -> Option<LogDirectory> {
    use std::time::UNIX_EPOCH;

    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    let mut last_modified: Option<u64> = None;

    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                file_count += 1;
                total_bytes += meta.len();
                if let Ok(modified) = meta.modified() {
                    if let Ok(secs) = modified.duration_since(UNIX_EPOCH) {
                        let s = secs.as_secs();
                        last_modified = Some(last_modified.map_or(s, |m| m.max(s)));
                    }
                }
            }
        }
    }

    if file_count == 0 {
        return None;
    }
    Some(LogDirectory {
        path: dir.to_path_buf(),
        file_count,
        total_bytes,
        last_modified,
    })
}
