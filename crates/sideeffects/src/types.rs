//! Shared, cross-platform result types for the side-effects scan. The per-OS
//! backends (`macos`, `windows`, `linux`) all populate these.

use std::path::PathBuf;

use serde::Serialize;

/// One native-messaging-host manifest that references the current app.
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

/// One helper / plugin / sibling executable that ships with the app, outside
/// its main binary.
#[derive(Debug, Clone, Serialize)]
pub struct BundleHelper {
    /// Name of the file or subdirectory.
    pub name: String,
    /// Absolute path.
    pub path: PathBuf,
    /// Total size in bytes (recurses into bundle directories). `None` on a
    /// permission issue.
    pub size_bytes: Option<u64>,
    /// Bundle id, if it's a macOS `.app` / `.xpc` we could read an Info.plist
    /// from.
    pub bundle_id: Option<String>,
    /// Version string from a sub-bundle's Info.plist, if present.
    pub version: Option<String>,
    /// True if the entry is a nested bundle directory rather than a raw file.
    pub is_bundle: bool,
}

/// Where an auto-start / background entry is registered.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // each variant is constructed on exactly one platform
pub enum LaunchScope {
    // macOS — launchd.
    /// `~/Library/LaunchAgents/` — runs on user login.
    UserAgent,
    /// `/Library/LaunchAgents/` — runs on every user's login (needs admin).
    GlobalAgent,
    /// `/Library/LaunchDaemons/` — runs as root at boot.
    Daemon,
    // Windows.
    /// `HKCU/HKLM …\Run` registry value.
    RunKey,
    /// A shortcut in a Startup folder.
    StartupFolder,
    /// A Task Scheduler task.
    ScheduledTask,
    /// A Windows service.
    Service,
    // Linux.
    /// `~/.config/autostart` / `/etc/xdg/autostart` `.desktop` entry.
    Autostart,
    /// A systemd user unit (`~/.config/systemd/user/*.service`).
    SystemdUser,
}

/// One auto-start / background-launch registration that references the app.
#[derive(Debug, Clone, Serialize)]
pub struct LaunchEntry {
    pub scope: LaunchScope,
    /// The source file (launchd plist / `.desktop` / `.service` / registry
    /// value) that registers the entry.
    pub plist_path: PathBuf,
    /// Identifier / label, where the format has one.
    pub label: Option<String>,
    /// The executable path or command line referenced.
    pub program: String,
    /// Runs immediately on registration / login?
    pub run_at_load: bool,
    /// Configured to be restarted if it exits?
    pub keep_alive: bool,
    pub modified_at: Option<u64>,
}

/// A per-app log / data directory outside the app's own install location.
#[derive(Debug, Clone, Serialize)]
pub struct LogDirectory {
    pub path: PathBuf,
    pub file_count: usize,
    pub total_bytes: u64,
    pub last_modified: Option<u64>,
}
