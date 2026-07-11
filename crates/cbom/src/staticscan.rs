//! Static binary crypto evidence.
//!
//! Complements the runtime (`netmon`) source: scans an app's binaries for the
//! cryptography it *links*, catching algorithms and libraries that a live
//! recording never exercised. Two signals:
//!
//! 1. **Linked libraries** — the binary's dynamic imports (`goblin`), matched
//!    against known crypto libraries (OpenSSL/BoringSSL/libsodium/…).
//! 2. **Symbols / strings** — distinctive crypto symbol and version-banner
//!    markers scanned from the binary bytes (mmap + memchr).
//!
//! Best-effort and heuristic: it reports what it can see, tagged
//! [`Provenance::StaticBinary`], and the aggregator dedupes it against observed
//! evidence.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use memmap2::Mmap;
use regex::bytes::Regex;

use crate::evidence::{CryptoEvidence, Provenance};

/// What a byte marker identifies.
enum Marker {
    /// A crypto library (distinctive, low-false-positive strings only).
    Library(&'static str),
    /// An algorithm, named so [`crate::normalize::named_algorithm`] maps it.
    Algorithm(&'static str),
}

/// All byte markers. Scanned in a **single** Aho-Corasick pass (a per-marker
/// `memmem` scan of large framework binaries is what made this slow). Library
/// markers are distinctive; ambiguous products (OpenSSL/LibreSSL/…) are gated on
/// a version *banner* ([`VERSION_RE`]) since their bare names appear in
/// unrelated binaries (Chromium references "OpenSSL"/"NSS" while using BoringSSL).
const MARKERS: &[(&[u8], Marker)] = &[
    (b"BoringSSL", Marker::Library("BoringSSL")),
    (b"BCryptEncrypt", Marker::Library("Windows CNG")),
    (b"CCCryptorCreate", Marker::Library("CommonCrypto")),
    (b"EVP_aes_256_gcm", Marker::Algorithm("aes-256-gcm")),
    (b"EVP_aes_128_gcm", Marker::Algorithm("aes-128-gcm")),
    (b"EVP_aes_256", Marker::Algorithm("aes-256")),
    (b"EVP_aes_128", Marker::Algorithm("aes-128")),
    (b"EVP_chacha20_poly1305", Marker::Algorithm("chacha20-poly1305")),
    (b"chacha20_poly1305", Marker::Algorithm("chacha20-poly1305")),
    (b"EVP_sha256", Marker::Algorithm("sha256")),
    (b"SHA256_Init", Marker::Algorithm("sha256")),
    (b"CC_SHA256", Marker::Algorithm("sha256")),
    (b"EVP_sha512", Marker::Algorithm("sha512")),
    (b"SHA512_Init", Marker::Algorithm("sha512")),
    (b"EVP_sha1", Marker::Algorithm("sha1")),
    (b"SHA1_Init", Marker::Algorithm("sha1")),
    (b"CC_SHA1", Marker::Algorithm("sha1")),
    (b"EVP_md5", Marker::Algorithm("md5")),
    (b"MD5_Init", Marker::Algorithm("md5")),
    (b"CC_MD5", Marker::Algorithm("md5")),
    (b"RSA_new", Marker::Algorithm("rsa")),
    (b"RSA_private_encrypt", Marker::Algorithm("rsa")),
    (b"ECDSA_do_sign", Marker::Algorithm("ecdsa")),
    (b"EC_KEY_new", Marker::Algorithm("ecdsa")),
    (b"ED25519_sign", Marker::Algorithm("ed25519")),
    (b"ed25519_", Marker::Algorithm("ed25519")),
    (b"DES_ede3", Marker::Algorithm("3des")),
    (b"RC4_set_key", Marker::Algorithm("rc4")),
];

static MARKER_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(MARKERS.iter().map(|(needle, _)| needle)).unwrap());

/// Crypto library filename patterns (for linked-import names and bundle walk).
fn crypto_library_from_name(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    let has = |n: &str| l.contains(n);
    if has("boringssl") {
        Some("BoringSSL")
    } else if has("libressl") {
        Some("LibreSSL")
    } else if has("sodium") {
        Some("libsodium")
    } else if has("mbedtls") || has("mbedcrypto") {
        Some("mbedTLS")
    } else if has("gnutls") {
        Some("GnuTLS")
    } else if has("wolfssl") {
        Some("wolfSSL")
    } else if has("libnss") || has("nspr") || has("freebl") || has("softokn") {
        Some("NSS")
    } else if has("bcrypt") || has("ncrypt") {
        Some("Windows CNG")
    } else if has("crypt32") {
        Some("Windows CryptoAPI")
    } else if has("commoncrypto") {
        Some("CommonCrypto")
    } else {
        None
    }
    // NB: bare libcrypto/libssl are intentionally omitted — they're ambiguous
    // (OpenSSL vs LibreSSL vs BoringSSL); the version-banner markers disambiguate.
}

/// A product version *banner* like `OpenSSL 3.3.1` / `libsodium 1.0.20`.
/// Group 1 = product, group 2 = version. Requiring the version disambiguates a
/// real library from an incidental name mention.
static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(OpenSSL|LibreSSL|libsodium|mbed TLS|GnuTLS|wolfSSL)[ /]v?(\d+\.\d+(?:\.\d+)?[a-z]?)")
        .unwrap()
});

/// Canonical library name for a `VERSION_RE` product capture.
fn banner_product(raw: &str) -> &'static str {
    match raw {
        "OpenSSL" => "OpenSSL",
        "LibreSSL" => "LibreSSL",
        "libsodium" => "libsodium",
        "mbed TLS" => "mbedTLS",
        "GnuTLS" => "GnuTLS",
        "wolfSSL" => "wolfSSL",
        _ => "crypto library",
    }
}

/// Scan an application's binaries for statically-linked cryptography.
/// `executable` is the primary binary; `root` (if given) is the bundle dir,
/// walked for bundled crypto libraries.
pub fn scan(executable: &Path, root: Option<&Path>) -> Vec<CryptoEvidence> {
    let mut ev = Vec::new();
    scan_binary(executable, &mut ev);
    if let Some(root) = root {
        for lib in candidate_binaries(root) {
            scan_binary(&lib, &mut ev);
        }
    }
    dedupe(ev)
}

fn scan_binary(path: &Path, out: &mut Vec<CryptoEvidence>) {
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    // Safety: read-only mapping, never aliased mutably.
    let Ok(mmap) = (unsafe { Mmap::map(&file) }) else {
        return;
    };
    let loc = path.to_string_lossy().into_owned();

    // Linked crypto libraries (imports).
    for lib in linked_libraries(&mmap) {
        if let Some(name) = crypto_library_from_name(&lib) {
            out.push(CryptoEvidence::Library {
                name: name.to_string(),
                version: None,
                provenance: Provenance::StaticBinary,
                location: Some(loc.clone()),
            });
        }
    }

    // Version-bannered products (e.g. "OpenSSL 3.3.1") — high confidence.
    if let Some(caps) = VERSION_RE.captures(&mmap) {
        let product = caps
            .get(1)
            .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
            .map(banner_product);
        let version = caps
            .get(2)
            .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
            .map(str::to_owned);
        if let Some(product) = product {
            out.push(CryptoEvidence::Library {
                name: product.to_string(),
                version,
                provenance: Provenance::StaticBinary,
                location: Some(loc.clone()),
            });
        }
    }
    // All distinctive library/algorithm markers in one Aho-Corasick pass, then
    // emit evidence for each marker that hit.
    let mut hit: std::collections::HashSet<usize> = std::collections::HashSet::new();
    // Overlapping so a longer marker (`EVP_aes_256_gcm`) isn't shadowed by a
    // shorter prefix (`EVP_aes_256`); duplicate assets dedupe in aggregation.
    for m in MARKER_AC.find_overlapping_iter(&*mmap) {
        hit.insert(m.pattern().as_usize());
    }
    for idx in hit {
        match &MARKERS[idx].1 {
            Marker::Library(name) => out.push(CryptoEvidence::Library {
                name: name.to_string(),
                version: None,
                provenance: Provenance::StaticBinary,
                location: Some(loc.clone()),
            }),
            Marker::Algorithm(name) => out.push(CryptoEvidence::Algorithm {
                name: name.to_string(),
                provenance: Provenance::StaticBinary,
                location: Some(loc.clone()),
            }),
        }
    }
}

/// Dynamic-library import names from a Mach-O / ELF / PE binary.
fn linked_libraries(bytes: &[u8]) -> Vec<String> {
    match goblin::Object::parse(bytes) {
        Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) => {
            macho.libs.iter().map(|s| s.to_string()).collect()
        }
        Ok(goblin::Object::Elf(elf)) => elf.libraries.iter().map(|s| s.to_string()).collect(),
        Ok(goblin::Object::PE(pe)) => pe.libraries.iter().map(|s| s.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// Binaries under the bundle worth scanning for crypto: crypto-named shared
/// libraries **and** framework main binaries (where statically-linked crypto
/// like BoringSSL in CEF/Electron lives). Bounded, and it doesn't descend into
/// symlinked dirs (avoids `Versions/Current` loops).
fn candidate_binaries(root: &Path) -> Vec<PathBuf> {
    const MAX_FILES: usize = 24;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if out.len() >= MAX_FILES {
                return out;
            }
            let path = entry.path();
            // Only descend into real directories (not symlinked ones).
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            let crypto_lib = (lower.ends_with(".dylib") || lower.ends_with(".so") || lower.ends_with(".dll"))
                && crypto_library_from_name(&lower).is_some();
            if crypto_lib || is_framework_main(&path, name) {
                out.push(path);
            }
        }
    }
    out
}

/// A framework's main binary: `<Name>.framework/**/<Name>` (no extension).
fn is_framework_main(path: &Path, name: &str) -> bool {
    if name.contains('.') {
        return false;
    }
    let fw = format!("{name}.framework");
    path.ancestors()
        .any(|a| a.file_name().and_then(|n| n.to_str()) == Some(fw.as_str()))
}

/// Deduplicate identical evidence (same kind + identity), ignoring location.
fn dedupe(ev: Vec<CryptoEvidence>) -> Vec<CryptoEvidence> {
    let mut seen = std::collections::HashSet::new();
    ev.into_iter()
        .filter(|e| {
            let key = match e {
                CryptoEvidence::Library { name, .. } => format!("lib:{name}"),
                CryptoEvidence::Algorithm { name, .. } => format!("alg:{name}"),
                _ => return true,
            };
            seen.insert(key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte-marker path is the testable core (no real binary needed).
    #[test]
    fn markers_produce_library_and_algorithm_evidence() {
        // Emulate a binary's string table with OpenSSL + AES-256-GCM markers.
        let blob = b"...random...OpenSSL 3.3.1...EVP_aes_256_gcm...ECDSA_do_sign...";
        let tmp = std::env::temp_dir().join("cbom-staticscan-test.bin");
        std::fs::write(&tmp, blob).unwrap();

        let ev = scan(&tmp, None);
        let has_lib = ev.iter().any(|e| {
            matches!(e, CryptoEvidence::Library { name, version, .. }
                if name == "OpenSSL" && version.as_deref() == Some("3.3.1"))
        });
        let has_aes = ev.iter().any(|e| {
            matches!(e, CryptoEvidence::Algorithm { name, .. } if name == "aes-256-gcm")
        });
        let has_ecdsa = ev.iter().any(|e| {
            matches!(e, CryptoEvidence::Algorithm { name, .. } if name == "ecdsa")
        });
        assert!(has_lib, "OpenSSL 3.3.1 library evidence");
        assert!(has_aes, "AES-256-GCM algorithm evidence");
        assert!(has_ecdsa, "ECDSA algorithm evidence");

        let _ = std::fs::remove_file(&tmp);
    }
}
