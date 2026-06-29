//! macOS audit backend: entitlements, `codesign` authority chain, Info.plist
//! hardening flags, and `ElectronAsarIntegrity` verification.

use std::path::{Path, PathBuf};

mod code_signature;
mod entitlements;
mod info_plist;

pub use code_signature::CodeSignature;
pub use entitlements::Entitlements;
pub use info_plist::{InfoPlistFlags, TlsException};

use crate::asar::AsarIntegrityCheck;

#[derive(Debug, Clone, serde::Serialize)]
pub struct MacosAudit {
    pub path: PathBuf,
    pub entitlements: Entitlements,
    pub code_signature: CodeSignature,
    pub info_plist: InfoPlistFlags,
    /// One entry per ASAR archive declared in `ElectronAsarIntegrity`.
    /// `None` for non-Electron bundles.
    pub asar_integrity: Option<Vec<AsarIntegrityCheck>>,
}

/// Audit the `.app` bundle at `app_path`. Signature + entitlements come from
/// shelling out to `codesign` (the `codesign` feature, native-only); on builds
/// without it (e.g. wasm) those fields are left at their defaults and only the
/// Info.plist + ASAR-integrity facts — which need no external tools — are filled.
pub async fn audit(app_path: &Path) -> MacosAudit {
    #[cfg(feature = "codesign")]
    let code_signature = code_signature::read(app_path).await;
    #[cfg(not(feature = "codesign"))]
    let code_signature = CodeSignature::default();

    #[cfg(feature = "codesign")]
    let entitlements = entitlements::read(app_path).await;
    #[cfg(not(feature = "codesign"))]
    let entitlements = Entitlements::default();

    let info_plist = info_plist::read(app_path);
    let asar_integrity = crate::asar::verify_all(app_path);

    MacosAudit {
        path: app_path.to_path_buf(),
        entitlements,
        code_signature,
        info_plist,
        asar_integrity,
    }
}
