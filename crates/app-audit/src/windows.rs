//! Windows audit backend.
//!
//! The analog of macOS's signing + hardened-runtime report is:
//!
//! * **Authenticode**: whether the PE carries an embedded signature, the
//!   signer certificate (subject + issuer, parsed from the embedded PKCS#7),
//!   and whether the OS trust store accepts the signature
//!   (`WinVerifyTrust`).
//! * **PE hardening**: the `DllCharacteristics` mitigation bits — ASLR
//!   (`DYNAMIC_BASE`), DEP (`NX_COMPAT`), Control Flow Guard (`GUARD_CF`), and
//!   high-entropy (64-bit) ASLR.
//! * **Manifest**: the `requestedExecutionLevel` (asInvoker vs
//!   requireAdministrator) embedded in the application manifest.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::asar::{self, AsarInfo};

// `DllCharacteristics` mitigation bits (winnt.h).
const DYNAMIC_BASE: u16 = 0x0040; // ASLR
const HIGH_ENTROPY_VA: u16 = 0x0020; // 64-bit ASLR
const NX_COMPAT: u16 = 0x0100; // DEP
const GUARD_CF: u16 = 0x4000; // Control Flow Guard

// WIN_CERTIFICATE.wCertificateType — the only type Authenticode uses.
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

#[derive(Debug, Clone, Serialize)]
pub struct WindowsAudit {
    pub path: PathBuf,
    pub signature: WindowsSignature,
    pub hardening: PeHardening,
    pub manifest: WindowsManifest,
    /// Informational ASAR hash for Electron apps (no signed baseline here).
    pub asar: Option<AsarInfo>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WindowsSignature {
    /// The PE carries an embedded Authenticode certificate table.
    pub signed: bool,
    /// Whether the OS trust store accepts the signature (chain valid, not
    /// revoked, root trusted). `None` if it couldn't be evaluated.
    pub trusted: Option<bool>,
    /// Signer certificate subject (distinguished name, e.g.
    /// `CN=Example Corp, O=Example Corp, C=US`).
    pub subject: Option<String>,
    /// Signer certificate issuer (the CA that issued the signing cert).
    pub issuer: Option<String>,
    /// Extra context (e.g. why trust couldn't be evaluated).
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PeHardening {
    /// Parsed a PE at all. `false` ⇒ the rest are meaningless.
    pub is_pe: bool,
    /// ASLR (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`).
    pub aslr: bool,
    /// DEP / NX (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`).
    pub dep: bool,
    /// Control Flow Guard (`IMAGE_DLLCHARACTERISTICS_GUARD_CF`).
    pub cfg: bool,
    /// High-entropy (64-bit) ASLR.
    pub high_entropy_va: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WindowsManifest {
    /// `asInvoker`, `highestAvailable`, or `requireAdministrator` if declared.
    pub requested_execution_level: Option<String>,
}

pub fn audit(path: &Path, root: &Path, executable: Option<&Path>) -> WindowsAudit {
    let bytes = executable.and_then(|exe| std::fs::read(exe).ok());

    let (mut signature, hardening) = match bytes.as_deref().map(parse_pe) {
        Some((sig, hard)) => (sig, hard),
        None => (WindowsSignature::default(), PeHardening::default()),
    };

    // Trust verification consults the OS store and needs the file path.
    if signature.signed {
        if let Some(exe) = executable {
            signature.trusted = verify_trust(exe);
        }
    }

    let manifest = WindowsManifest {
        requested_execution_level: bytes.as_deref().and_then(scan_execution_level),
    };
    let asar = asar::info(root);

    WindowsAudit {
        path: path.to_path_buf(),
        signature,
        hardening,
        manifest,
        asar,
    }
}

fn parse_pe(bytes: &[u8]) -> (WindowsSignature, PeHardening) {
    let pe = match goblin::Object::parse(bytes) {
        Ok(goblin::Object::PE(pe)) => pe,
        _ => return (WindowsSignature::default(), PeHardening::default()),
    };

    let Some(oh) = pe.header.optional_header else {
        return (
            WindowsSignature {
                note: Some("no optional header".into()),
                ..WindowsSignature::default()
            },
            PeHardening {
                is_pe: true,
                ..PeHardening::default()
            },
        );
    };

    let dchar = oh.windows_fields.dll_characteristics;
    let hardening = PeHardening {
        is_pe: true,
        aslr: dchar & DYNAMIC_BASE != 0,
        dep: dchar & NX_COMPAT != 0,
        cfg: dchar & GUARD_CF != 0,
        high_entropy_va: dchar & HIGH_ENTROPY_VA != 0,
    };

    // The certificate table (security directory) holds the Authenticode blob.
    // Its `virtual_address` is a *file offset*, not an RVA (a PE quirk).
    let cert_dir = oh.data_directories.get_certificate_table();
    let signed = cert_dir.map(|d| d.size > 0).unwrap_or(false);

    let mut signature = WindowsSignature {
        signed,
        ..WindowsSignature::default()
    };
    if let Some(dir) = cert_dir.filter(|d| d.size > 0) {
        match extract_signer(bytes, dir.virtual_address as usize, dir.size as usize) {
            Some((subject, issuer)) => {
                signature.subject = Some(subject);
                signature.issuer = Some(issuer);
            }
            None => {
                signature.note = Some("signature present; signer certificate unparsed".into());
            }
        }
    }

    (signature, hardening)
}

/// Parse the embedded PKCS#7 certificate table to recover the signer
/// certificate's subject and issuer distinguished names.
fn extract_signer(bytes: &[u8], start: usize, size: usize) -> Option<(String, String)> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::{SignedData, SignerIdentifier};
    use x509_cert::der::Decode;

    let table = bytes.get(start..start.checked_add(size)?)?;
    if table.len() < 8 {
        return None;
    }
    // WIN_CERTIFICATE: dwLength(u32), wRevision(u16), wCertificateType(u16),
    // then the PKCS#7 DER blob.
    let dw_length = u32::from_le_bytes(table[0..4].try_into().ok()?) as usize;
    let cert_type = u16::from_le_bytes(table[6..8].try_into().ok()?);
    if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return None;
    }
    let der = table.get(8..dw_length)?;

    let content_info = ContentInfo::from_der(der).ok()?;
    let signed_data: SignedData = content_info.content.decode_as().ok()?;
    let certificates = signed_data.certificates?;

    // The leaf signer is identified by the first SignerInfo's issuer+serial.
    let signer = signed_data.signer_infos.0.iter().next();
    let sid = signer.map(|s| &s.sid);

    let mut fallback: Option<(String, String)> = None;
    for choice in certificates.0.iter() {
        let CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        let tbs = &cert.tbs_certificate;
        let names = (tbs.subject.to_string(), tbs.issuer.to_string());

        if let Some(SignerIdentifier::IssuerAndSerialNumber(ias)) = sid {
            if tbs.serial_number == ias.serial_number && tbs.issuer == ias.issuer {
                return Some(names);
            }
        }
        fallback.get_or_insert(names);
    }
    // No exact signer match (e.g. SubjectKeyIdentifier sid) — use the first
    // certificate, which is conventionally the leaf.
    fallback
}

/// Verify the file's Authenticode signature against the OS trust store.
fn verify_trust(exe: &Path) -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    let wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: every struct is either zero-initialised (all fields are pointers /
    // integers, for which all-zero is a valid null/default) or has the required
    // fields set below; `wide` outlives the call.
    unsafe {
        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = PCWSTR(wide.as_ptr());

        let mut wtd: WINTRUST_DATA = std::mem::zeroed();
        wtd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE;
        wtd.Anonymous.pFile = &mut file_info;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut wtd as *mut _ as *mut core::ffi::c_void,
        );

        // Release the state data regardless of the verdict.
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut wtd as *mut _ as *mut core::ffi::c_void,
        );

        // ERROR_SUCCESS (0) ⇒ the signature is trusted; any TRUST_E_* ⇒ not.
        Some(status == 0)
    }
}

/// Scan the embedded application manifest for
/// `<requestedExecutionLevel level="…">`. The manifest is an `RT_MANIFEST`
/// resource but its XML appears verbatim in the file, so a byte search finds it
/// without parsing the resource tree.
fn scan_execution_level(bytes: &[u8]) -> Option<String> {
    let anchor = find(bytes, b"requestedExecutionLevel")?;
    let window = &bytes[anchor..bytes.len().min(anchor + 256)];
    let level_at = find(window, b"level=")?;
    let after = &window[level_at + b"level=".len()..];
    // Value is quoted: `level="asInvoker"`.
    let quote = *after.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &after[1..];
    let end = rest.iter().position(|&b| b == quote)?;
    std::str::from_utf8(&rest[..end]).ok().map(str::to_owned)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}
