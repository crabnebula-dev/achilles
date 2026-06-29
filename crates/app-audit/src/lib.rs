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
#[cfg(all(target_os = "linux", not(macos_layout)))]
mod linux;
#[cfg(macos_layout)]
mod macos;
#[cfg(all(target_os = "windows", not(macos_layout)))]
mod windows;

pub use asar::{AsarInfo, AsarIntegrityCheck};

#[cfg(all(target_os = "linux", not(macos_layout)))]
pub use linux::{ElfHardening, LinuxAudit, RelroKind, SandboxInfo};
#[cfg(macos_layout)]
pub use macos::{CodeSignature, Entitlements, InfoPlistFlags, MacosAudit, TlsException};

/// Read and parse a property list through [`vfs`] (real fs on native, the
/// in-memory upload tree on wasm). `None` if missing or malformed.
#[cfg(macos_layout)]
pub(crate) fn read_plist(path: &Path) -> Option<plist::Value> {
    plist::Value::from_reader(std::io::Cursor::new(vfs::read(path).ok()?)).ok()
}
#[cfg(all(target_os = "windows", not(macos_layout)))]
pub use windows::{PeHardening, WindowsAudit, WindowsManifest, WindowsSignature};

/// Platform-tagged audit result. Each variant flattens its fields alongside a
/// `"platform"` discriminant in JSON, so the frontend branches on
/// `audit.platform`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum AppAudit {
    #[cfg(macos_layout)]
    Macos(MacosAudit),
    #[cfg(all(target_os = "windows", not(macos_layout)))]
    Windows(WindowsAudit),
    #[cfg(all(target_os = "linux", not(macos_layout)))]
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
    if !vfs::exists(path) {
        return Err(AuditError::NotFound(path.to_path_buf()));
    }

    #[cfg(macos_layout)]
    {
        let _ = (root, executable);
        Ok(AppAudit::Macos(macos::audit(path).await))
    }
    #[cfg(all(target_os = "windows", not(macos_layout)))]
    {
        Ok(AppAudit::Windows(windows::audit(path, root, executable)))
    }
    #[cfg(all(target_os = "linux", not(macos_layout)))]
    {
        Ok(AppAudit::Linux(linux::audit(path, root, executable)))
    }
    #[cfg(not(any(macos_layout, target_os = "windows", target_os = "linux")))]
    {
        let _ = (root, executable);
        Ok(AppAudit::Unsupported {
            path: path.to_path_buf(),
        })
    }
}
