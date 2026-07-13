//! Shared crypto-evidence types produced by every source (runtime `netmon`
//! capture, static binary analysis, …) and consumed by the aggregator.

use serde::{Deserialize, Serialize};

/// Where a piece of evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Provenance {
    /// Seen on the wire during a live capture.
    ObservedRuntime,
    /// Found by static analysis of the app's binaries.
    StaticBinary,
}

/// Security-protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolFamily {
    Tls,
    Ssh,
    Ipsec,
    Other,
}

/// One observation of cryptography in use. Sources emit these; the aggregator
/// normalizes them into canonical crypto-assets. TLS registry code points
/// (cipher suites, groups, signature schemes) are kept as their numeric ids so
/// normalization owns the id→algorithm mapping in one place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CryptoEvidence {
    /// A protocol instance, e.g. TLS 1.3.
    Protocol {
        family: ProtocolFamily,
        /// Human version, e.g. `"1.2"`, `"1.3"`.
        version: Option<String>,
        provenance: Provenance,
        /// `"host:port"` (observed) or a binary path (static).
        location: Option<String>,
    },
    /// A TLS cipher suite by IANA code point.
    CipherSuite {
        id: u16,
        /// Negotiated (`true`) vs merely offered in a ClientHello (`false`).
        selected: bool,
        provenance: Provenance,
        location: Option<String>,
    },
    /// A named group / key-exchange parameter (TLS `supported_groups`).
    Group {
        id: u16,
        provenance: Provenance,
        location: Option<String>,
    },
    /// A TLS signature scheme (`signature_algorithms`).
    SignatureScheme {
        id: u16,
        provenance: Provenance,
        location: Option<String>,
    },
    /// A directly-named algorithm (static symbol / OID / cert field).
    Algorithm {
        /// Free-form name; normalization maps it to a canonical asset.
        name: String,
        provenance: Provenance,
        location: Option<String>,
    },
    /// An X.509 certificate observed in a handshake (TLS ≤1.2 only).
    Certificate {
        subject: Option<String>,
        issuer: Option<String>,
        signature_algorithm: Option<String>,
        /// e.g. `"RSA-2048"`, `"EC-P256"`.
        public_key_algorithm: Option<String>,
        not_before: Option<i64>,
        not_after: Option<i64>,
        self_signed: bool,
        provenance: Provenance,
        location: Option<String>,
    },
    /// A crypto library linked into the app (usually static evidence).
    Library {
        /// e.g. `"OpenSSL"`, `"BoringSSL"`, `"libsodium"`.
        name: String,
        version: Option<String>,
        provenance: Provenance,
        location: Option<String>,
    },
}

impl CryptoEvidence {
    pub fn provenance(&self) -> Provenance {
        match self {
            CryptoEvidence::Protocol { provenance, .. }
            | CryptoEvidence::CipherSuite { provenance, .. }
            | CryptoEvidence::Group { provenance, .. }
            | CryptoEvidence::SignatureScheme { provenance, .. }
            | CryptoEvidence::Algorithm { provenance, .. }
            | CryptoEvidence::Certificate { provenance, .. }
            | CryptoEvidence::Library { provenance, .. } => *provenance,
        }
    }

    pub fn location(&self) -> Option<&str> {
        match self {
            CryptoEvidence::Protocol { location, .. }
            | CryptoEvidence::CipherSuite { location, .. }
            | CryptoEvidence::Group { location, .. }
            | CryptoEvidence::SignatureScheme { location, .. }
            | CryptoEvidence::Algorithm { location, .. }
            | CryptoEvidence::Certificate { location, .. }
            | CryptoEvidence::Library { location, .. } => location.as_deref(),
        }
    }
}
