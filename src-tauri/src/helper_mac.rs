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
///
/// Idempotent: registering an already-enabled service is a no-op success, so
/// callers (the install button, the Record path) can call it freely.
pub fn install() -> Result<(), String> {
    if unsafe { service().status() } == SMAppServiceStatus::Enabled {
        return Ok(());
    }
    unsafe { service().registerAndReturnError() }.map_err(|e| e.localizedDescription().to_string())
}

/// Re-validate an existing registration at launch, so an app update (which
/// replaces the bundled helper binary and plist in place) keeps a working
/// daemon without a second trip through System Settings — the signature is
/// unchanged, so no re-approval is prompted.
///
/// Deliberately only re-registers what the user already approved: a fresh
/// install stays user-initiated (the banner's button, or pressing Record), so
/// merely launching Achilles never plants a root daemon.
pub fn revalidate_on_launch() {
    if unsafe { service().status() } == SMAppServiceStatus::Enabled {
        let _ = unsafe { service().registerAndReturnError() };
    }
}

/// Whether the helper's socket is live — i.e. launchd has actually started the
/// daemon and captures will get real per-app attribution. `status()` alone
/// can't tell you this: it reads `enabled` from the moment the user approves,
/// while the socket appears a moment later. Probes by connecting, so a stale
/// socket file left by an unregistered/stopped daemon reads as *not* ready.
pub fn socket_ready() -> bool {
    netmon::helper_reachable()
}

/// Unregister the daemon, returning status to `notRegistered` — launchd stops
/// and unloads it. Lets a user remove the helper, and makes the install/approval
/// flow repeatable when testing. Idempotent: a no-op success when nothing is
/// registered (avoids the `kSMErrorJobNotFound` the API returns in that case).
pub fn uninstall() -> Result<(), String> {
    let status = unsafe { service().status() };
    if status == SMAppServiceStatus::NotRegistered || status == SMAppServiceStatus::NotFound {
        return Ok(());
    }
    unsafe { service().unregisterAndReturnError() }
        .map_err(|e| e.localizedDescription().to_string())
}

/// Open System Settings → General → Login Items & Extensions for approval.
pub fn open_login_items() {
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}
