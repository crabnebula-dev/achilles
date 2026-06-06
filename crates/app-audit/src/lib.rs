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

use std::path::{Path, PathBuf};

mod asar;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub use asar::{AsarInfo, AsarIntegrityCheck};

#[cfg(target_os = "linux")]
pub use linux::{ElfHardening, LinuxAudit, RelroKind, SandboxInfo};
#[cfg(target_os = "macos")]
pub use macos::{CodeSignature, Entitlements, InfoPlistFlags, MacosAudit, TlsException};
#[cfg(target_os = "windows")]
pub use windows::{PeHardening, WindowsAudit, WindowsManifest, WindowsSignature};

/// Platform-tagged audit result. Each variant flattens its fields alongside a
/// `"platform"` discriminant in JSON, so the frontend branches on
/// `audit.platform`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum AppAudit {
    #[cfg(target_os = "macos")]
    Macos(MacosAudit),
    #[cfg(target_os = "windows")]
    Windows(WindowsAudit),
    #[cfg(target_os = "linux")]
    Linux(LinuxAudit),
    /// A platform with no native audit backend in this build.
    Unsupported { path: PathBuf },
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
pub async fn audit(
    path: &Path,
    root: &Path,
    executable: Option<&Path>,
) -> Result<AppAudit, AuditError> {
    if !path.exists() {
        return Err(AuditError::NotFound(path.to_path_buf()));
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (root, executable);
        Ok(AppAudit::Macos(macos::audit(path).await))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(AppAudit::Windows(windows::audit(path, root, executable)))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(AppAudit::Linux(linux::audit(path, root, executable)))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (root, executable);
        Ok(AppAudit::Unsupported {
            path: path.to_path_buf(),
        })
    }
}
