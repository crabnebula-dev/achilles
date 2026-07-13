//! Cryptography Bill of Materials (CBOM).
//!
//! Aggregates cryptographic **evidence** — from runtime observation (the
//! `netmon` network monitor) and from static binary analysis — into a
//! deduplicated per-application inventory of cryptographic assets, classifies
//! each asset's post-quantum readiness (NIST quantum-security level), and
//! exports a standards-based **CycloneDX 1.6 CBOM**.
//!
//! Pipeline: [`CryptoEvidence`] (from any source) → [`build_inventory`] →
//! [`CryptoInventory`] → [`to_cyclonedx`].

mod aggregate;
mod cyclonedx;
mod evidence;
mod model;
mod normalize;
mod staticscan;

pub use evidence::{CryptoEvidence, ProtocolFamily, Provenance};
pub use model::{
    AppRef, AssetType, CertSummary, CryptoAsset, CryptoInventory, Dependency, Primitive,
    ProtocolInfo, QuantumAssessment, QuantumReadiness,
};

/// Aggregate evidence into a per-application crypto inventory.
pub fn build_inventory(app: AppRef, evidence: &[CryptoEvidence]) -> CryptoInventory {
    aggregate::build(app, evidence)
}

/// Static crypto evidence from an app's binaries — linked crypto libraries and
/// algorithm symbols. `executable` is the primary binary; `root` (the bundle
/// dir, if any) is walked for bundled crypto libraries. Tagged
/// [`Provenance::StaticBinary`].
pub fn static_evidence(
    executable: &std::path::Path,
    root: Option<&std::path::Path>,
) -> Vec<CryptoEvidence> {
    staticscan::scan(executable, root)
}

/// Serialize an inventory to a CycloneDX 1.6 CBOM document.
pub fn to_cyclonedx(inventory: &CryptoInventory) -> serde_json::Value {
    cyclonedx::to_bom(inventory)
}
