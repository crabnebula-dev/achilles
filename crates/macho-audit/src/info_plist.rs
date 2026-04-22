//! Surface hardening-relevant fields from `Contents/Info.plist`.
//!
//! The goal isn't to reproduce every property — just the ones that materially
//! change the app's security posture:
//!
//! - `NSAllowsArbitraryLoads` and domain-specific ATS exceptions
//! - Registered URL schemes (an attack surface for any scheme handler)
//! - TLS minimum-version and insecure-HTTP exception dicts

use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct InfoPlistFlags {
    /// Did we find and parse `Contents/Info.plist` at all.
    pub present: bool,
    /// `NSAppTransportSecurity.NSAllowsArbitraryLoads`. Usually a red flag.
    pub allows_arbitrary_loads: bool,
    /// `NSAppTransportSecurity.NSAllowsLocalNetworking`.
    pub allows_local_networking: bool,
    /// Every URL scheme the bundle registers (`CFBundleURLTypes`).
    pub url_schemes: Vec<String>,
    /// Per-domain TLS exceptions from `NSExceptionDomains`.
    pub tls_exceptions: Vec<TlsException>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsException {
    pub domain: String,
    pub allows_insecure_http: bool,
    pub minimum_tls_version: Option<String>,
    pub requires_forward_secrecy: bool,
}

pub fn read(app_path: &Path) -> InfoPlistFlags {
    let plist_path = app_path.join("Contents/Info.plist");
    let Ok(value) = plist::Value::from_file(&plist_path) else {
        return InfoPlistFlags::default();
    };
    let Some(dict) = value.as_dictionary() else {
        return InfoPlistFlags::default();
    };

    let mut flags = InfoPlistFlags {
        present: true,
        ..Default::default()
    };

    if let Some(ats) = dict.get("NSAppTransportSecurity").and_then(|v| v.as_dictionary()) {
        flags.allows_arbitrary_loads = ats
            .get("NSAllowsArbitraryLoads")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);
        flags.allows_local_networking = ats
            .get("NSAllowsLocalNetworking")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);

        if let Some(domains) = ats
            .get("NSExceptionDomains")
            .and_then(|v| v.as_dictionary())
        {
            for (domain, entry) in domains {
                let Some(entry) = entry.as_dictionary() else {
                    continue;
                };
                flags.tls_exceptions.push(TlsException {
                    domain: domain.clone(),
                    allows_insecure_http: entry
                        .get("NSTemporaryExceptionAllowsInsecureHTTPLoads")
                        .or_else(|| entry.get("NSExceptionAllowsInsecureHTTPLoads"))
                        .and_then(|v| v.as_boolean())
                        .unwrap_or(false),
                    minimum_tls_version: entry
                        .get("NSTemporaryExceptionMinimumTLSVersion")
                        .or_else(|| entry.get("NSExceptionMinimumTLSVersion"))
                        .and_then(|v| v.as_string())
                        .map(str::to_owned),
                    requires_forward_secrecy: entry
                        .get("NSTemporaryExceptionRequiresForwardSecrecy")
                        .or_else(|| entry.get("NSExceptionRequiresForwardSecrecy"))
                        .and_then(|v| v.as_boolean())
                        .unwrap_or(true),
                });
            }
        }
    }

    if let Some(url_types) = dict.get("CFBundleURLTypes").and_then(|v| v.as_array()) {
        for url_type in url_types {
            let Some(t) = url_type.as_dictionary() else {
                continue;
            };
            if let Some(schemes) = t.get("CFBundleURLSchemes").and_then(|v| v.as_array()) {
                for s in schemes {
                    if let Some(scheme) = s.as_string() {
                        flags.url_schemes.push(scheme.to_owned());
                    }
                }
            }
        }
    }

    flags
}
