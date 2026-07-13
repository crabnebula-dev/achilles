use cbom::{
    build_inventory, to_cyclonedx, AppRef, CryptoEvidence, ProtocolFamily, Provenance,
    QuantumAssessment,
};

fn app() -> AppRef {
    AppRef {
        name: "Example".into(),
        version: Some("1.0".into()),
        bundle_id: Some("com.example.app".into()),
        path: Some("/Applications/Example.app".into()),
    }
}

fn observed_tls12_evidence() -> Vec<CryptoEvidence> {
    vec![
        CryptoEvidence::Protocol {
            family: ProtocolFamily::Tls,
            version: Some("1.2".into()),
            provenance: Provenance::ObservedRuntime,
            location: Some("example.com:443".into()),
        },
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        CryptoEvidence::CipherSuite {
            id: 0xC02F,
            selected: true,
            provenance: Provenance::ObservedRuntime,
            location: Some("example.com:443".into()),
        },
        // x25519 group
        CryptoEvidence::Group {
            id: 0x001D,
            provenance: Provenance::ObservedRuntime,
            location: Some("example.com:443".into()),
        },
        // OpenSSL linked (static)
        CryptoEvidence::Library {
            name: "OpenSSL".into(),
            version: Some("3.3.1".into()),
            provenance: Provenance::StaticBinary,
            location: Some("/Applications/Example.app/libssl.3.dylib".into()),
        },
    ]
}

#[test]
fn cipher_suite_decomposes_into_classified_primitives() {
    let inv = build_inventory(app(), &observed_tls12_evidence());
    let by_ref = |r: &str| inv.assets.iter().find(|a| a.bom_ref == r);

    // The suite decomposed into its four primitives.
    for r in [
        "crypto/algorithm/ecdhe",
        "crypto/algorithm/rsa",
        "crypto/algorithm/aes-128-gcm",
        "crypto/algorithm/sha256",
    ] {
        assert!(by_ref(r).is_some(), "missing {r}");
    }

    // ECDHE + RSA are quantum-vulnerable (NIST level 0); AES-128 is acceptable.
    assert_eq!(by_ref("crypto/algorithm/ecdhe").unwrap().assessment, QuantumAssessment::QuantumVulnerable);
    assert_eq!(by_ref("crypto/algorithm/ecdhe").unwrap().nist_level, 0);
    assert_eq!(by_ref("crypto/algorithm/rsa").unwrap().assessment, QuantumAssessment::QuantumVulnerable);
    assert_eq!(by_ref("crypto/algorithm/aes-128-gcm").unwrap().assessment, QuantumAssessment::Acceptable);
    assert_eq!(by_ref("crypto/algorithm/aes-128-gcm").unwrap().nist_level, 1);

    // x25519 group + TLS 1.2 protocol + OpenSSL library are all present.
    assert!(by_ref("crypto/algorithm/x25519").is_some());
    let proto = by_ref("crypto/protocol/tls-1.2").expect("protocol asset");
    assert_eq!(
        proto.protocol.as_ref().unwrap().cipher_suites,
        vec!["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string()]
    );
    let lib = by_ref("crypto/library/openssl").expect("library asset");
    assert_eq!(lib.library_version.as_deref(), Some("3.3.1"));
    assert!(lib.provenance.contains(&Provenance::StaticBinary));

    // Rollup flags the quantum-vulnerable posture.
    assert_eq!(inv.readiness.grade, "vulnerable");
    assert!(inv.readiness.quantum_vulnerable >= 3); // ecdhe, rsa, x25519
}

#[test]
fn exports_valid_cyclonedx_cbom() {
    let inv = build_inventory(app(), &observed_tls12_evidence());
    let bom = to_cyclonedx(&inv);

    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.6");
    assert_eq!(bom["metadata"]["component"]["type"], "application");

    let comps = bom["components"].as_array().unwrap();
    // An algorithm crypto-asset carries a NIST quantum-security level.
    let ecdhe = comps
        .iter()
        .find(|c| c["bom-ref"] == "crypto/algorithm/ecdhe")
        .expect("ecdhe component");
    assert_eq!(ecdhe["type"], "cryptographic-asset");
    assert_eq!(ecdhe["cryptoProperties"]["assetType"], "algorithm");
    assert_eq!(ecdhe["cryptoProperties"]["algorithmProperties"]["primitive"], "key-agree");
    assert_eq!(
        ecdhe["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
        0
    );

    // The protocol component records its cipher suites.
    let proto = comps
        .iter()
        .find(|c| c["cryptoProperties"]["assetType"] == "protocol")
        .expect("protocol component");
    assert_eq!(proto["cryptoProperties"]["protocolProperties"]["type"], "tls");

    // OpenSSL is a library component (not a crypto-asset).
    let lib = comps
        .iter()
        .find(|c| c["bom-ref"] == "crypto/library/openssl")
        .expect("library component");
    assert_eq!(lib["type"], "library");
    assert_eq!(lib["version"], "3.3.1");

    // Dependencies: the app depends on the protocol, and the protocol uses the
    // primitive algorithms.
    let deps = bom["dependencies"].as_array().unwrap();
    let app_dep = deps.iter().find(|d| d["ref"] == "application").unwrap();
    assert!(app_dep["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "crypto/protocol/tls-1.2"));
    let proto_dep = deps.iter().find(|d| d["ref"] == "crypto/protocol/tls-1.2").unwrap();
    assert!(proto_dep["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "crypto/algorithm/ecdhe"));
}
