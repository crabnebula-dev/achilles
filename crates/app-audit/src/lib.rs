//! Audit an installed application for code-signing / integrity / hardening,
//! across macOS, Windows, and Linux.
//!
//! The reportable facts differ per platform, so [`AppAudit`] is a
//! `#[serde(tag = "platform")]` enum:
//!
//! * **macOS**: hardened-runtime entitlements, `codesign` authority chain,
//!   Info.plist hardening flags, and `ElectronAsarIntegrity` verification.
//! * **Windows**: Authenticode signature presence, PE hardening flags
//!   (ASLR / DEP / CFG / high-entropy VA), and the manifest's requested
//!   execution level.
//! * **Linux**: ELF hardening (PIE / RELRO / NX / stack-canary) and, for
//!   flatpak/snap apps, the declared sandbox permissions.
//!
//! ASAR integrity is reported on every platform for Electron apps.
//!
//! Which backend runs is [`vfs::platform`]: the host OS on the desktop (a
//! compile-time constant, so the other two fold away), and on wasm the platform
//! of whatever the browser was handed. All three are therefore always compiled.
//! The few facts that genuinely need the host OS — `codesign`'s authority chain,
//! `WinVerifyTrust`'s verdict — degrade to `None` with a note elsewhere.

use std::path::{Path, PathBuf};

use vfs::Platform;

mod asar;
mod linux;
mod macos;
mod windows;

pub use asar::{AsarInfo, AsarIntegrityCheck};
pub use linux::{ElfHardening, LinuxAudit, RelroKind, SandboxInfo};
pub use macos::{CodeSignature, Entitlements, InfoPlistFlags, MacosAudit, TlsException};
pub use windows::{PeHardening, WindowsAudit, WindowsManifest, WindowsSignature};

/// Read and parse a property list through [`vfs`] (real fs on native, the
/// in-memory upload tree on wasm). `None` if missing or malformed.
pub(crate) fn read_plist(path: &Path) -> Option<plist::Value> {
    plist::Value::from_reader(std::io::Cursor::new(vfs::read(path).ok()?)).ok()
}

/// Platform-tagged audit result. Each variant flattens its fields alongside a
/// `"platform"` discriminant in JSON, so the frontend branches on
/// `audit.platform`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum AppAudit {
    Macos(MacosAudit),
    Windows(WindowsAudit),
    Linux(LinuxAudit),
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("path not found: {0}")]
    NotFound(PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Audit the app identified by `path` (its stable identity), rooted at `root`
/// (where sibling files live), with primary `executable`. Returns a best-effort
/// report; every subcomponent has its own "nothing found" representation rather
/// than failing the whole audit.
/// `codesign` summary for any file or bundle (macOS; unsigned elsewhere).
pub async fn code_signature(path: &Path) -> CodeSignature {
    macos::code_signature_of(path).await
}

pub async fn audit(
    path: &Path,
    root: &Path,
    executable: Option<&Path>,
) -> Result<AppAudit, AuditError> {
    if !vfs::exists(path) {
        return Err(AuditError::NotFound(path.to_path_buf()));
    }

    Ok(match vfs::platform() {
        Platform::Macos => AppAudit::Macos(macos::audit(path).await),
        Platform::Windows => AppAudit::Windows(windows::audit(path, root, executable)),
        Platform::Linux => AppAudit::Linux(linux::audit(path, root, executable)),
    })
}
