//! Canonical crypto-asset model and the aggregated inventory.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::evidence::Provenance;

/// The application a CBOM describes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRef {
    pub name: String,
    pub version: Option<String>,
    pub bundle_id: Option<String>,
    pub path: Option<String>,
}

/// CycloneDX crypto-asset class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetType {
    Algorithm,
    Protocol,
    Certificate,
    RelatedMaterial,
    /// Not a CycloneDX crypto-asset — exported as a `library` component.
    Library,
}

/// CycloneDX `algorithmProperties.primitive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    BlockCipher,
    StreamCipher,
    Hash,
    Mac,
    Signature,
    KeyAgree,
    Kem,
    Kdf,
    Drbg,
    Pke,
    Other,
}

/// Post-quantum / classical readiness bucket for UI grouping. Maps to a
/// CycloneDX `nistQuantumSecurityLevel` on export (see [`QuantumAssessment::nist_level`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuantumAssessment {
    /// Classical asymmetric broken by Shor's algorithm (RSA, ECDH/ECDSA, DH).
    QuantumVulnerable,
    /// Classically broken already (MD5, SHA-1, RC4, DES, export ciphers).
    ClassicallyBroken,
    /// Legacy/borderline (3DES, SHA-1 signatures, TLS 1.0/1.1).
    Weak,
    /// Acceptable classical strength (AES-128, SHA-256).
    Acceptable,
    /// Strong classical strength (AES-256, SHA-384/512).
    Strong,
    /// Post-quantum algorithm (ML-KEM, ML-DSA, SLH-DSA).
    PostQuantum,
    /// A container/protocol with no intrinsic strength of its own.
    NotApplicable,
    Unknown,
}

impl QuantumAssessment {
    /// CycloneDX `nistQuantumSecurityLevel` (0 = none/quantum-vulnerable/unknown,
    /// 1..=5 = NIST PQC categories). `param` optionally refines PQC param sets.
    pub fn nist_level(self, param: Option<&str>) -> u8 {
        match self {
            QuantumAssessment::QuantumVulnerable
            | QuantumAssessment::ClassicallyBroken
            | QuantumAssessment::NotApplicable
            | QuantumAssessment::Unknown => 0,
            QuantumAssessment::Weak | QuantumAssessment::Acceptable => 1,
            QuantumAssessment::Strong => 5,
            QuantumAssessment::PostQuantum => match param {
                Some(p) if p.contains("512") => 1,
                Some(p) if p.contains("768") => 3,
                Some(p) if p.contains("1024") => 5,
                _ => 3,
            },
        }
    }

    /// Whether this asset must be migrated for post-quantum readiness.
    pub fn is_quantum_risk(self) -> bool {
        matches!(
            self,
            QuantumAssessment::QuantumVulnerable | QuantumAssessment::ClassicallyBroken
        )
    }
}

/// Protocol-asset extras (TLS version + the suites seen under it).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolInfo {
    pub version: Option<String>,
    /// bom-refs of cipher-suite assets negotiated/offered under this protocol.
    pub cipher_suites: Vec<String>,
}

/// Certificate-asset extras.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertSummary {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub self_signed: bool,
    pub signature_algorithm: Option<String>,
    pub public_key_algorithm: Option<String>,
}

/// One deduplicated cryptographic asset in the inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoAsset {
    /// Stable, human-readable id (also the CycloneDX `bom-ref`).
    pub bom_ref: String,
    pub asset_type: AssetType,
    pub name: String,
    pub oid: Option<String>,
    pub primitive: Option<Primitive>,
    /// Key size / curve / parameter set, e.g. `"128"`, `"P-256"`, `"ML-KEM-768"`.
    pub parameter: Option<String>,
    /// CycloneDX `cryptoFunctions`, e.g. `["encrypt","decrypt"]`.
    pub crypto_functions: Vec<String>,
    pub assessment: QuantumAssessment,
    pub nist_level: u8,
    pub deprecated: bool,
    pub provenance: BTreeSet<Provenance>,
    pub occurrences: u32,
    pub locations: BTreeSet<String>,
    pub protocol: Option<ProtocolInfo>,
    pub certificate: Option<CertSummary>,
    pub library_version: Option<String>,
}

/// A CycloneDX-style provides/uses edge (`ref` dependsOn `depends_on`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    pub bom_ref: String,
    pub depends_on: Vec<String>,
}

/// Rollup of post-quantum readiness across the inventory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuantumReadiness {
    pub total_assets: u32,
    pub quantum_vulnerable: u32,
    pub classically_broken: u32,
    pub weak: u32,
    pub post_quantum: u32,
    /// Overall grade: `"vulnerable"` if any quantum-vulnerable/broken assets,
    /// `"at-risk"` if any weak, else `"ok"`.
    pub grade: String,
}

/// The aggregated per-application crypto inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoInventory {
    pub app: AppRef,
    pub assets: Vec<CryptoAsset>,
    pub dependencies: Vec<Dependency>,
    pub readiness: QuantumReadiness,
}
