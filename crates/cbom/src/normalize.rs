//! Normalization tables: turn raw evidence (TLS registry code points, algorithm
//! names) into canonical, quantum-classified crypto-asset descriptors.
//!
//! Coverage is representative, not exhaustive — the common TLS 1.2/1.3 suites,
//! groups, signature schemes, and the primitives they decompose into, plus the
//! algorithm families seen in certs and static binary symbols. Extend the
//! tables as new evidence appears; each entry is self-contained.

use crate::evidence::ProtocolFamily;
use crate::model::{AssetType, Primitive, QuantumAssessment};

/// A canonical asset descriptor before provenance/occurrence aggregation.
#[derive(Debug, Clone)]
pub(crate) struct Canon {
    pub bom_ref: String,
    pub name: String,
    pub asset_type: AssetType,
    pub primitive: Option<Primitive>,
    pub parameter: Option<String>,
    pub oid: Option<String>,
    pub crypto_functions: Vec<String>,
    pub assessment: QuantumAssessment,
    pub deprecated: bool,
}

fn algo(
    slug: &str,
    name: &str,
    primitive: Primitive,
    parameter: Option<&str>,
    assessment: QuantumAssessment,
) -> Canon {
    let funcs: &[&str] = match primitive {
        Primitive::BlockCipher | Primitive::StreamCipher | Primitive::Pke => &["encrypt", "decrypt"],
        Primitive::Hash => &["digest"],
        Primitive::Mac => &["digest"],
        Primitive::Signature => &["sign", "verify"],
        Primitive::KeyAgree => &["keygen"],
        Primitive::Kem => &["encapsulate", "decapsulate"],
        Primitive::Kdf => &["keyderive"],
        Primitive::Drbg | Primitive::Other => &["generate"],
    };
    Canon {
        bom_ref: format!("crypto/algorithm/{slug}"),
        name: name.to_string(),
        asset_type: AssetType::Algorithm,
        primitive: Some(primitive),
        parameter: parameter.map(str::to_string),
        oid: None,
        crypto_functions: funcs.iter().map(|s| s.to_string()).collect(),
        assessment,
        deprecated: matches!(
            assessment,
            QuantumAssessment::ClassicallyBroken | QuantumAssessment::Weak
        ),
    }
}

// --- primitive builders (each returns a fresh Canon) --------------------

fn ecdhe() -> Canon {
    algo("ecdhe", "ECDHE", Primitive::KeyAgree, None, QuantumAssessment::QuantumVulnerable)
}
fn rsa_kx() -> Canon {
    algo("rsa-kex", "RSA (key transport)", Primitive::Pke, None, QuantumAssessment::QuantumVulnerable)
}
fn rsa_sig() -> Canon {
    algo("rsa", "RSA", Primitive::Signature, None, QuantumAssessment::QuantumVulnerable)
}
fn ecdsa() -> Canon {
    algo("ecdsa", "ECDSA", Primitive::Signature, None, QuantumAssessment::QuantumVulnerable)
}
fn ed25519() -> Canon {
    algo("ed25519", "Ed25519", Primitive::Signature, Some("Ed25519"), QuantumAssessment::QuantumVulnerable)
}
fn aes(bits: u32, mode: &str, strong: bool) -> Canon {
    let a = if strong { QuantumAssessment::Strong } else { QuantumAssessment::Acceptable };
    algo(
        &format!("aes-{bits}-{}", mode.to_lowercase()),
        &format!("AES-{bits}-{mode}"),
        Primitive::BlockCipher,
        Some(&bits.to_string()),
        a,
    )
}
fn chacha20() -> Canon {
    algo(
        "chacha20-poly1305",
        "ChaCha20-Poly1305",
        Primitive::StreamCipher,
        Some("256"),
        QuantumAssessment::Strong,
    )
}
fn tripledes() -> Canon {
    algo("3des", "3DES-EDE-CBC", Primitive::BlockCipher, Some("112"), QuantumAssessment::Weak)
}
fn rc4() -> Canon {
    algo("rc4", "RC4", Primitive::StreamCipher, Some("128"), QuantumAssessment::ClassicallyBroken)
}
fn sha(bits: u32) -> Canon {
    let a = if bits >= 384 { QuantumAssessment::Strong } else { QuantumAssessment::Acceptable };
    algo(&format!("sha{bits}"), &format!("SHA-{bits}"), Primitive::Hash, Some(&bits.to_string()), a)
}
fn sha1() -> Canon {
    algo("sha1", "SHA-1", Primitive::Hash, Some("160"), QuantumAssessment::ClassicallyBroken)
}
fn md5() -> Canon {
    algo("md5", "MD5", Primitive::Hash, Some("128"), QuantumAssessment::ClassicallyBroken)
}
fn ml_kem(param: &str) -> Canon {
    algo(
        &format!("ml-kem-{}", param.trim_start_matches("ML-KEM-")),
        &format!("ML-KEM ({param})"),
        Primitive::Kem,
        Some(param),
        QuantumAssessment::PostQuantum,
    )
}
fn ml_dsa(param: &str) -> Canon {
    algo(&format!("ml-dsa-{param}"), &format!("ML-DSA ({param})"), Primitive::Signature, Some(param), QuantumAssessment::PostQuantum)
}

// --- TLS cipher-suite registry (representative) -------------------------

/// Decompose a TLS cipher suite into its (name, component algorithms).
pub(crate) fn cipher_suite(id: u16) -> Option<(String, Vec<Canon>)> {
    let (name, components): (&str, Vec<Canon>) = match id {
        // TLS 1.3 (AEAD + hash; key exchange & auth negotiated separately)
        0x1301 => ("TLS_AES_128_GCM_SHA256", vec![aes(128, "GCM", false), sha(256)]),
        0x1302 => ("TLS_AES_256_GCM_SHA384", vec![aes(256, "GCM", true), sha(384)]),
        0x1303 => ("TLS_CHACHA20_POLY1305_SHA256", vec![chacha20(), sha(256)]),
        // TLS 1.2 ECDHE-AEAD
        0xC02B => ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", vec![ecdhe(), ecdsa(), aes(128, "GCM", false), sha(256)]),
        0xC02F => ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", vec![ecdhe(), rsa_sig(), aes(128, "GCM", false), sha(256)]),
        0xC02C => ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", vec![ecdhe(), ecdsa(), aes(256, "GCM", true), sha(384)]),
        0xC030 => ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", vec![ecdhe(), rsa_sig(), aes(256, "GCM", true), sha(384)]),
        0xCCA9 => ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", vec![ecdhe(), ecdsa(), chacha20(), sha(256)]),
        0xCCA8 => ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", vec![ecdhe(), rsa_sig(), chacha20(), sha(256)]),
        // Legacy / weak
        0x009C => ("TLS_RSA_WITH_AES_128_GCM_SHA256", vec![rsa_kx(), aes(128, "GCM", false), sha(256)]),
        0x002F => ("TLS_RSA_WITH_AES_128_CBC_SHA", vec![rsa_kx(), aes(128, "CBC", false), sha1()]),
        0x000A => ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", vec![rsa_kx(), tripledes(), sha1()]),
        0x0005 => ("TLS_RSA_WITH_RC4_128_SHA", vec![rsa_kx(), rc4(), sha1()]),
        _ => return None,
    };
    Some((name.to_string(), components))
}

// --- TLS supported_groups (representative) ------------------------------

pub(crate) fn group(id: u16) -> Option<Canon> {
    Some(match id {
        0x0017 => algo("secp256r1", "ECDH secp256r1 (P-256)", Primitive::KeyAgree, Some("P-256"), QuantumAssessment::QuantumVulnerable),
        0x0018 => algo("secp384r1", "ECDH secp384r1 (P-384)", Primitive::KeyAgree, Some("P-384"), QuantumAssessment::QuantumVulnerable),
        0x001D => algo("x25519", "X25519", Primitive::KeyAgree, Some("X25519"), QuantumAssessment::QuantumVulnerable),
        0x001E => algo("x448", "X448", Primitive::KeyAgree, Some("X448"), QuantumAssessment::QuantumVulnerable),
        0x0100 => algo("ffdhe2048", "FFDHE-2048", Primitive::KeyAgree, Some("2048"), QuantumAssessment::QuantumVulnerable),
        // Hybrid PQC key exchange (RFC drafts / deployed in browsers).
        0x11EC | 0x6399 => {
            let mut c = ml_kem("ML-KEM-768");
            c.bom_ref = "crypto/algorithm/x25519mlkem768".into();
            c.name = "X25519MLKEM768 (hybrid)".into();
            c.parameter = Some("X25519MLKEM768".into());
            c.primitive = Some(Primitive::KeyAgree);
            c
        }
        _ => return None,
    })
}

// --- TLS signature_algorithms (representative) --------------------------

pub(crate) fn signature_scheme(id: u16) -> Option<Canon> {
    Some(match id {
        0x0401 | 0x0501 | 0x0601 => rsa_sig(),                     // rsa_pkcs1_sha256/384/512
        0x0804..=0x0806 => rsa_sig(),                              // rsa_pss_*
        0x0403 => ecdsa(),                                          // ecdsa_secp256r1_sha256
        0x0503 => ecdsa(),                                          // ecdsa_secp384r1_sha384
        0x0807 => ed25519(),                                        // ed25519
        0x0201 => {
            let mut c = rsa_sig();
            c.assessment = QuantumAssessment::Weak; // rsa_pkcs1_sha1
            c.deprecated = true;
            c
        }
        0x0904..=0x0906 => ml_dsa("ML-DSA-65"),                     // provisional ML-DSA code points
        _ => return None,
    })
}

// --- named-algorithm fuzzy match (static symbols / cert fields) ---------

/// Best-effort mapping of a free-form algorithm name (a cert `sigAlg`, a
/// static symbol, an OID-derived label) to a canonical asset.
pub(crate) fn named_algorithm(raw: &str) -> Option<Canon> {
    let n = raw.to_ascii_lowercase();
    let has = |needle: &str| n.contains(needle);
    Some(match () {
        _ if has("ml-kem") || has("kyber") => ml_kem("ML-KEM-768"),
        _ if has("ml-dsa") || has("dilithium") => ml_dsa("ML-DSA-65"),
        _ if has("ed25519") => ed25519(),
        _ if has("ecdsa") => ecdsa(),
        _ if has("ecdh") => algo("ecdh", "ECDH", Primitive::KeyAgree, None, QuantumAssessment::QuantumVulnerable),
        _ if has("rsa") => rsa_sig(),
        _ if has("chacha") => chacha20(),
        _ if has("aes") && has("256") => aes(256, "GCM", true),
        _ if has("aes") && has("128") => aes(128, "GCM", false),
        _ if has("aes") => aes(128, "GCM", false),
        _ if has("3des") || has("des-ede") => tripledes(),
        _ if has("rc4") => rc4(),
        _ if has("sha512") || has("sha-512") || has("sha384") || has("sha-384") => sha(384),
        _ if has("sha256") || has("sha-256") => sha(256),
        _ if has("sha1") || has("sha-1") => sha1(),
        _ if has("md5") => md5(),
        _ => return None,
    })
}

// --- protocol + library assets ------------------------------------------

pub(crate) fn protocol(family: ProtocolFamily, version: Option<&str>) -> Canon {
    let fam = match family {
        ProtocolFamily::Tls => "tls",
        ProtocolFamily::Ssh => "ssh",
        ProtocolFamily::Ipsec => "ipsec",
        ProtocolFamily::Other => "protocol",
    };
    let ver = version.unwrap_or("unknown");
    // TLS 1.0/1.1 (and any SSL) are deprecated; TLS 1.2/1.3 are containers with
    // no intrinsic strength of their own (their algorithms carry it).
    let is_legacy = matches!(family, ProtocolFamily::Tls)
        && matches!(version, Some(v) if v == "1.0" || v == "1.1" || v.eq_ignore_ascii_case("ssl") || v.starts_with('3'));
    let (assessment, deprecated) = if is_legacy {
        (QuantumAssessment::Weak, true)
    } else {
        (QuantumAssessment::NotApplicable, false)
    };
    Canon {
        bom_ref: format!("crypto/protocol/{fam}-{ver}"),
        name: format!("{} {}", fam.to_uppercase(), ver),
        asset_type: AssetType::Protocol,
        primitive: None,
        parameter: None,
        oid: None,
        crypto_functions: vec![],
        assessment,
        deprecated,
    }
}

pub(crate) fn library(name: &str, _version: Option<&str>) -> Canon {
    let slug: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    Canon {
        bom_ref: format!("crypto/library/{slug}"),
        name: name.to_string(),
        asset_type: AssetType::Library,
        primitive: None,
        parameter: None,
        oid: None,
        crypto_functions: vec![],
        assessment: QuantumAssessment::NotApplicable,
        deprecated: false,
    }
}
