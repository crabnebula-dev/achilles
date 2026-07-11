//! macOS privileged-helper management via `SMAppService`.
//!
//! Registers the bundled root LaunchDaemon (see
//! `macos/LaunchDaemons/dev.crabnebula.achilles.netmon.plist`) so it can capture
//! via `pktap` without elevating the app. No special entitlement is required —
//! only that the app + helper are signed with the same Developer ID (which the
//! release pipeline already does).

use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

const PLIST_NAME: &str = "dev.crabnebula.achilles.netmon.plist";

fn service() -> Retained<SMAppService> {
    let name = NSString::from_str(PLIST_NAME);
    unsafe { SMAppService::daemonServiceWithPlistName(&name) }
}

/// Current registration status as a stable string for the UI.
pub fn status_str() -> &'static str {
    let status = unsafe { service().status() };
    if status == SMAppServiceStatus::Enabled {
        "enabled"
    } else if status == SMAppServiceStatus::RequiresApproval {
        "requiresApproval"
    } else if status == SMAppServiceStatus::NotRegistered {
        "notRegistered"
    } else if status == SMAppServiceStatus::NotFound {
        "notFound"
    } else {
        "unknown"
    }
}

/// Register the daemon. First call typically moves status to `requiresApproval`;
/// the user then enables it in System Settings.
pub fn install() -> Result<(), String> {
    unsafe { service().registerAndReturnError() }.map_err(|e| e.localizedDescription().to_string())
}

/// Open System Settings → General → Login Items & Extensions for approval.
pub fn open_login_items() {
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}
