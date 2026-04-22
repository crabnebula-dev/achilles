//! Detect the system-level side effects a macOS app leaves *outside* its
//! own bundle. These are the things a purely-in-bundle audit can't see:
//!
//! - **Inside the bundle** (but easily missed): helpers in `Contents/Helpers/`,
//!   plugin bundles in `Contents/PlugIns/`, XPC services in
//!   `Contents/XPCServices/`.
//! - **Outside the bundle**: native-messaging-host manifests dropped into
//!   browser profile directories, `launchd` agents / daemons, log
//!   directories under `~/Library/Logs/`.
//!
//! Each of these can be perfectly legitimate — helper apps for rendering,
//! browser bridges for integrations, launch agents for background services
//! — but they're often installed silently by apps without any UI
//! indication. Surfacing them is a prerequisite for informed user consent.
//!
//! # Design
//!
//! - [`analyse`] is the one-shot entry point. Given an app bundle, it
//!   returns every side-effect we could identify.
//! - Cross-app scans (native-messaging hosts, launch agents) are keyed by
//!   the bundle's `CFBundleIdentifier` and its main executable path, so an
//!   app that wrote a manifest referencing its own helper can be matched.
//! - All I/O is blocking; run it inside `tokio::task::spawn_blocking`.
//!
//! Macho-only for the moment; paths are macOS-specific.

use std::path::{Path, PathBuf};

use serde::Serialize;

mod browsers;
mod bundle_internal;
mod launch;
mod logs;

pub use browsers::NativeMessagingHost;
pub use bundle_internal::BundleHelper;
pub use launch::LaunchEntry;
pub use logs::LogDirectory;

/// Every side-effect we detected for one bundle.
#[derive(Debug, Clone, Serialize)]
pub struct SideEffects {
    pub app_path: PathBuf,

    /// Helper `.app` bundles under `Contents/Helpers/`.
    pub helpers: Vec<BundleHelper>,
    /// Anything under `Contents/PlugIns/` (plugin bundles, loadable
    /// resources). Electron-style apps put their renderer-helper apps
    /// here too.
    pub plugins: Vec<BundleHelper>,
    /// XPC services bundled under `Contents/XPCServices/`.
    pub xpc_services: Vec<BundleHelper>,

    /// Native-messaging-host manifests in browser profile dirs whose
    /// `path` field points back into *this* app's bundle.
    pub native_messaging_hosts: Vec<NativeMessagingHost>,

    /// `launchd` agents / daemons whose `Program` or `ProgramArguments[0]`
    /// points back into this bundle.
    pub launch_entries: Vec<LaunchEntry>,

    /// `~/Library/Logs/<name>/` directory, if present.
    pub log_dir: Option<LogDirectory>,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Enumerate every side-effect for the bundle at `app_path`. `bundle_id`
/// and `executable` are passed explicitly (not re-read) so callers that
/// already have a `detect::Detection` don't pay for another plist parse.
pub fn analyse(
    app_path: &Path,
    bundle_id: Option<&str>,
    executable: Option<&Path>,
) -> Result<SideEffects, AnalyseError> {
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
