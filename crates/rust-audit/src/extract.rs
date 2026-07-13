//! Extract the `cargo-auditable` dependency list embedded in a Rust binary.
//!
//! `cargo auditable build` stores a zlib-compressed JSON dependency tree in a
//! `.dep-v0` linker section (ELF/PE/Mach-O). We locate it with
//! `auditable-extract`, inflate it, and read the crate names + versions.

use std::io::Read;

use serde::Deserialize;

/// One crate recorded in a binary's embedded audit data.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditedCrate {
    pub name: String,
    pub version: semver::Version,
}

#[derive(Deserialize)]
struct VersionInfo {
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    /// Version as a string (the `semver` crate's serde support is off by
    /// default, so we parse it ourselves).
    version: String,
}

/// Parse the inflated `.dep-v0` JSON into crate name/version pairs. Crates whose
/// version doesn't parse as semver are skipped.
pub(crate) fn parse_version_info(json: &str) -> Option<Vec<AuditedCrate>> {
    let info: VersionInfo = serde_json::from_str(json).ok()?;
    Some(
        info.packages
            .into_iter()
            .filter_map(|p| {
                semver::Version::parse(&p.version)
                    .ok()
                    .map(|version| AuditedCrate { name: p.name, version })
            })
            .collect(),
    )
}

/// Extract the audit data from a binary's bytes, or `None` if it carries no
/// `cargo-auditable` section.
pub fn extract(binary: &[u8]) -> Option<Vec<AuditedCrate>> {
    let compressed = auditable_extract::raw_auditable_data(binary).ok()?;
    let mut json = String::new();
    flate2::read::ZlibDecoder::new(compressed)
        .read_to_string(&mut json)
        .ok()?;
    parse_version_info(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_auditable_json() {
        let json = r#"{"packages":[
            {"name":"foo","version":"1.2.0","source":"registry","kind":"runtime","root":true},
            {"name":"bar","version":"0.3.1","source":"registry","kind":"runtime"},
            {"name":"weird","version":"not-semver","source":"registry"}
        ]}"#;
        let crates = parse_version_info(json).unwrap();
        // `weird` is dropped (unparseable version).
        assert_eq!(crates.len(), 2);
        assert_eq!(crates[0].name, "foo");
        assert_eq!(crates[0].version, semver::Version::parse("1.2.0").unwrap());
    }
}
