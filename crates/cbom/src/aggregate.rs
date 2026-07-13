//! Aggregate raw evidence into a deduplicated [`CryptoInventory`] with a
//! provides/uses dependency graph and a post-quantum readiness rollup.

use std::collections::{BTreeMap, BTreeSet};

use crate::evidence::{CryptoEvidence, Provenance};
use crate::model::{
    AppRef, AssetType, CertSummary, CryptoAsset, CryptoInventory, Dependency, ProtocolInfo,
    QuantumAssessment, QuantumReadiness,
};
use crate::normalize::{self, Canon};

/// Root component bom-ref for the application.
const APP_REF: &str = "application";

fn asset_from_canon(c: &Canon) -> CryptoAsset {
    CryptoAsset {
        bom_ref: c.bom_ref.clone(),
        asset_type: c.asset_type,
        name: c.name.clone(),
        oid: c.oid.clone(),
        primitive: c.primitive,
        parameter: c.parameter.clone(),
        crypto_functions: c.crypto_functions.clone(),
        assessment: c.assessment,
        nist_level: c.assessment.nist_level(c.parameter.as_deref()),
        deprecated: c.deprecated,
        provenance: BTreeSet::new(),
        occurrences: 0,
        locations: BTreeSet::new(),
        protocol: None,
        certificate: None,
        library_version: None,
    }
}

/// Insert-or-merge a canonical asset, recording provenance/occurrence/location.
fn upsert(
    assets: &mut BTreeMap<String, CryptoAsset>,
    c: &Canon,
    prov: Provenance,
    loc: Option<&str>,
) -> String {
    let a = assets
        .entry(c.bom_ref.clone())
        .or_insert_with(|| asset_from_canon(c));
    a.occurrences += 1;
    a.provenance.insert(prov);
    if let Some(l) = loc {
        a.locations.insert(l.to_string());
    }
    c.bom_ref.clone()
}

pub(crate) fn build(app: AppRef, evidence: &[CryptoEvidence]) -> CryptoInventory {
    let mut assets: BTreeMap<String, CryptoAsset> = BTreeMap::new();
    let mut protocols: BTreeSet<String> = BTreeSet::new();
    let mut libraries: BTreeSet<String> = BTreeSet::new();
    let mut certs: Vec<(String, Vec<String>)> = Vec::new();
    // Algorithm assets that a protocol "uses" (suite primitives, groups, sigs).
    let mut primitives: BTreeSet<String> = BTreeSet::new();
    // Cipher-suite names observed, attached to protocol assets.
    let mut suite_names: BTreeSet<String> = BTreeSet::new();
    // Standalone algorithms with no protocol link (static symbols), under app.
    let mut loose: BTreeSet<String> = BTreeSet::new();

    for ev in evidence {
        let prov = ev.provenance();
        let loc = ev.location();
        match ev {
            CryptoEvidence::Protocol { family, version, .. } => {
                let c = normalize::protocol(*family, version.as_deref());
                protocols.insert(upsert(&mut assets, &c, prov, loc));
            }
            CryptoEvidence::CipherSuite { id, .. } => {
                if let Some((name, components)) = normalize::cipher_suite(*id) {
                    suite_names.insert(name);
                    for comp in &components {
                        primitives.insert(upsert(&mut assets, comp, prov, loc));
                    }
                }
            }
            CryptoEvidence::Group { id, .. } => {
                if let Some(c) = normalize::group(*id) {
                    primitives.insert(upsert(&mut assets, &c, prov, loc));
                }
            }
            CryptoEvidence::SignatureScheme { id, .. } => {
                if let Some(c) = normalize::signature_scheme(*id) {
                    primitives.insert(upsert(&mut assets, &c, prov, loc));
                }
            }
            CryptoEvidence::Algorithm { name, .. } => {
                if let Some(c) = normalize::named_algorithm(name) {
                    let r = upsert(&mut assets, &c, prov, loc);
                    // Runtime-named algorithms usually belong to a handshake;
                    // static ones stand alone under the app.
                    match prov {
                        Provenance::ObservedRuntime => primitives.insert(r),
                        Provenance::StaticBinary => loose.insert(r),
                    };
                }
            }
            CryptoEvidence::Certificate {
                subject,
                issuer,
                signature_algorithm,
                public_key_algorithm,
                not_before,
                not_after,
                self_signed,
                ..
            } => {
                // A certificate asset plus links to its sig + key algorithms.
                let mut algo_refs = Vec::new();
                if let Some(s) = signature_algorithm.as_deref().and_then(normalize::named_algorithm) {
                    algo_refs.push(upsert(&mut assets, &s, prov, loc));
                }
                if let Some(k) = public_key_algorithm.as_deref().and_then(normalize::named_algorithm) {
                    algo_refs.push(upsert(&mut assets, &k, prov, loc));
                }
                let cert_ref = format!(
                    "crypto/certificate/{}",
                    slug(subject.as_deref().or(issuer.as_deref()).unwrap_or("cert"))
                );
                let a = assets.entry(cert_ref.clone()).or_insert_with(|| CryptoAsset {
                    bom_ref: cert_ref.clone(),
                    asset_type: AssetType::Certificate,
                    name: subject.clone().unwrap_or_else(|| "certificate".into()),
                    oid: None,
                    primitive: None,
                    parameter: None,
                    crypto_functions: vec![],
                    assessment: if *self_signed {
                        QuantumAssessment::Weak
                    } else {
                        QuantumAssessment::NotApplicable
                    },
                    nist_level: 0,
                    deprecated: false,
                    provenance: BTreeSet::new(),
                    occurrences: 0,
                    locations: BTreeSet::new(),
                    protocol: None,
                    certificate: Some(CertSummary {
                        subject: subject.clone(),
                        issuer: issuer.clone(),
                        not_before: *not_before,
                        not_after: *not_after,
                        self_signed: *self_signed,
                        signature_algorithm: signature_algorithm.clone(),
                        public_key_algorithm: public_key_algorithm.clone(),
                    }),
                    library_version: None,
                });
                a.occurrences += 1;
                a.provenance.insert(prov);
                if let Some(l) = loc {
                    a.locations.insert(l.to_string());
                }
                certs.push((cert_ref, algo_refs));
            }
            CryptoEvidence::Library { name, version, .. } => {
                let c = normalize::library(name, version.as_deref());
                let r = upsert(&mut assets, &c, prov, loc);
                if let Some(a) = assets.get_mut(&r) {
                    if a.library_version.is_none() {
                        a.library_version = version.clone();
                    }
                }
                libraries.insert(r);
            }
        }
    }

    // Attach observed cipher-suite names to every TLS protocol asset.
    if !suite_names.is_empty() {
        let suites: Vec<String> = suite_names.iter().cloned().collect();
        for pref in &protocols {
            if let Some(a) = assets.get_mut(pref) {
                let info = a.protocol.get_or_insert_with(ProtocolInfo::default);
                info.version = a.name.split(' ').nth(1).map(str::to_string);
                info.cipher_suites = suites.clone();
            }
        }
    }

    // Dependency graph (provides/uses).
    let mut deps: Vec<Dependency> = Vec::new();
    // Protocols use the observed primitives; if no protocol, they hang off app.
    if protocols.is_empty() {
        loose.extend(primitives.iter().cloned());
    } else {
        let uses: Vec<String> = primitives.iter().cloned().collect();
        for pref in &protocols {
            deps.push(Dependency {
                bom_ref: pref.clone(),
                depends_on: uses.clone(),
            });
        }
    }
    for (cref, algos) in &certs {
        if !algos.is_empty() {
            deps.push(Dependency {
                bom_ref: cref.clone(),
                depends_on: algos.clone(),
            });
        }
    }
    // App depends on protocols, libraries, certs, and any loose algorithms.
    let mut app_uses: Vec<String> = Vec::new();
    app_uses.extend(protocols.iter().cloned());
    app_uses.extend(libraries.iter().cloned());
    app_uses.extend(certs.iter().map(|(r, _)| r.clone()));
    app_uses.extend(loose.iter().cloned());
    app_uses.sort();
    app_uses.dedup();
    deps.insert(
        0,
        Dependency {
            bom_ref: APP_REF.to_string(),
            depends_on: app_uses,
        },
    );

    let mut asset_vec: Vec<CryptoAsset> = assets.into_values().collect();
    asset_vec.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));

    let readiness = rollup(&asset_vec);
    CryptoInventory {
        app,
        assets: asset_vec,
        dependencies: deps,
        readiness,
    }
}

fn rollup(assets: &[CryptoAsset]) -> QuantumReadiness {
    let mut r = QuantumReadiness {
        total_assets: assets.len() as u32,
        ..Default::default()
    };
    for a in assets {
        match a.assessment {
            QuantumAssessment::QuantumVulnerable => r.quantum_vulnerable += 1,
            QuantumAssessment::ClassicallyBroken => r.classically_broken += 1,
            QuantumAssessment::Weak => r.weak += 1,
            QuantumAssessment::PostQuantum => r.post_quantum += 1,
            _ => {}
        }
    }
    r.grade = if r.quantum_vulnerable > 0 || r.classically_broken > 0 {
        "vulnerable"
    } else if r.weak > 0 {
        "at-risk"
    } else {
        "ok"
    }
    .to_string();
    r
}

fn slug(s: &str) -> String {
    let out: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    out.trim_matches('-').chars().take(48).collect()
}
