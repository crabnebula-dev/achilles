//! Serialize a [`CryptoInventory`] to a CycloneDX 1.6 CBOM document.
//!
//! Maps each canonical asset to a `cryptographic-asset` component (algorithm /
//! protocol / certificate) with `cryptoProperties`, detected crypto libraries
//! to `library` components, and the aggregated provides/uses edges to
//! `dependencies`. See <https://cyclonedx.org/capabilities/cbom/>.

use serde_json::{json, Value};

use crate::model::{AssetType, CryptoAsset, CryptoInventory, Primitive};

const APP_REF: &str = "application";

fn primitive_str(p: Primitive) -> &'static str {
    match p {
        Primitive::BlockCipher => "block-cipher",
        Primitive::StreamCipher => "stream-cipher",
        Primitive::Hash => "hash",
        Primitive::Mac => "mac",
        Primitive::Signature => "signature",
        Primitive::KeyAgree => "key-agree",
        Primitive::Kem => "kem",
        Primitive::Kdf => "kdf",
        Primitive::Drbg => "drbg",
        Primitive::Pke => "pke",
        Primitive::Other => "other",
    }
}

/// A parameter that names a curve vs a generic parameter set.
fn is_curve(param: &str) -> bool {
    let p = param.to_ascii_uppercase();
    p.starts_with('P') || p.contains("25519") || p.contains("448")
}

fn algorithm_component(a: &CryptoAsset) -> Value {
    let mut algo = json!({
        "cryptoFunctions": a.crypto_functions,
        "nistQuantumSecurityLevel": a.nist_level,
    });
    if let Some(p) = a.primitive {
        algo["primitive"] = json!(primitive_str(p));
    }
    if let Some(param) = &a.parameter {
        if is_curve(param) {
            algo["curve"] = json!(param);
        } else {
            algo["parameterSetIdentifier"] = json!(param);
        }
    }
    json!({
        "type": "cryptographic-asset",
        "bom-ref": a.bom_ref,
        "name": a.name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algo,
        },
    })
}

fn protocol_component(a: &CryptoAsset) -> Value {
    let mut props = json!({ "type": "tls" });
    if let Some(info) = &a.protocol {
        if let Some(v) = &info.version {
            props["version"] = json!(v);
        }
        if !info.cipher_suites.is_empty() {
            props["cipherSuites"] =
                json!(info.cipher_suites.iter().map(|n| json!({ "name": n })).collect::<Vec<_>>());
        }
    }
    json!({
        "type": "cryptographic-asset",
        "bom-ref": a.bom_ref,
        "name": a.name,
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": props,
        },
    })
}

fn certificate_component(a: &CryptoAsset) -> Value {
    let mut props = json!({});
    if let Some(c) = &a.certificate {
        if let Some(s) = &c.subject {
            props["subjectName"] = json!(s);
        }
        if let Some(i) = &c.issuer {
            props["issuerName"] = json!(i);
        }
        if let Some(alg) = &c.signature_algorithm {
            props["signatureAlgorithmName"] = json!(alg);
        }
    }
    json!({
        "type": "cryptographic-asset",
        "bom-ref": a.bom_ref,
        "name": a.name,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": props,
        },
    })
}

fn library_component(a: &CryptoAsset) -> Value {
    let mut c = json!({
        "type": "library",
        "bom-ref": a.bom_ref,
        "name": a.name,
    });
    if let Some(v) = &a.library_version {
        c["version"] = json!(v);
    }
    c
}

pub(crate) fn to_bom(inv: &CryptoInventory) -> Value {
    let components: Vec<Value> = inv
        .assets
        .iter()
        .map(|a| match a.asset_type {
            AssetType::Algorithm | AssetType::RelatedMaterial => algorithm_component(a),
            AssetType::Protocol => protocol_component(a),
            AssetType::Certificate => certificate_component(a),
            AssetType::Library => library_component(a),
        })
        .collect();

    let dependencies: Vec<Value> = inv
        .dependencies
        .iter()
        .filter(|d| !d.depends_on.is_empty())
        .map(|d| json!({ "ref": d.bom_ref, "dependsOn": d.depends_on }))
        .collect();

    let mut app_component = json!({
        "type": "application",
        "bom-ref": APP_REF,
        "name": inv.app.name,
    });
    if let Some(v) = &inv.app.version {
        app_component["version"] = json!(v);
    }
    if let Some(b) = &inv.app.bundle_id {
        app_component["cpe"] = Value::Null; // placeholder; bundle id kept in properties
        app_component["properties"] = json!([{ "name": "bundleId", "value": b }]);
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": { "component": app_component },
        "components": components,
        "dependencies": dependencies,
    })
}
