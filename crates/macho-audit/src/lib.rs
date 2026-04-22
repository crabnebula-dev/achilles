//! Audit a macOS `.app` bundle for entitlements, code-signing, Info.plist
//! hardening flags, and ASAR integrity.
//!
//! Everything here is macOS-only; on other platforms the public API still
//! compiles but [`audit`] returns an [`AuditError::Unsupported`].

use std::path::{Path, PathBuf};

mod asar;
mod code_signature;
mod entitlements;
mod info_plist;

pub use asar::AsarIntegrityCheck;
pub use code_signature::CodeSignature;
pub use entitlements::Entitlements;
pub use info_plist::{InfoPlistFlags, TlsException};

#[derive(Debug, Clone, serde::Serialize)]
pub struct MachoAudit {
    pub path: PathBuf,
    pub entitlements: Entitlements,
    pub code_signature: CodeSignature,
    pub info_plist: InfoPlistFlags,
    /// One entry per ASAR archive declared in `ElectronAsarIntegrity`.
    /// `None` for non-Electron bundles.
    pub asar_integrity: Option<Vec<AsarIntegrityCheck>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("path not found: {0}")]
    NotFound(PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit is only supported on macOS in this build")]
    Unsupported,
}

/// Audit the bundle at `app_path`. Returns a best-effort report; every
/// subcomponent has its own "nothing found" representation rather than
/// failing the whole audit.
pub async fn audit(app_path: &Path) -> Result<MachoAudit, AuditError> {
    if !app_path.exists() {
        return Err(AuditError::NotFound(app_path.to_path_buf()));
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = app_path;
        return Err(AuditError::Unsupported);
    }

    #[cfg(target_os = "macos")]
    {
        let code_signature = code_signature::read(app_path).await;
        let entitlements = entitlements::read(app_path).await;
        let info_plist = info_plist::read(app_path);
        let asar_integrity = asar::verify_all(app_path);

        Ok(MachoAudit {
            path: app_path.to_path_buf(),
            entitlements,
            code_signature,
            info_plist,
            asar_integrity,
        })
    }
}
