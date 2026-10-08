//! Open-source license composition for an application.
//!
//! Aggregates the licenses of the pieces an app ships — its runtime/framework,
//! linked native libraries, bundled npm dependencies, and embedded Rust crates —
//! and classifies each by copyleft strength so the UI can surface compliance
//! risk (permissive vs. weak/strong copyleft vs. undetermined).
//!
//! The classification tables and curated component maps here are offline and
//! pure; the network path that resolves Rust crate licenses lives in
//! [`crates_io`].

pub mod crates_io;

use std::collections::BTreeMap;

use serde::Serialize;

/// How restrictive a license is, from a redistribution standpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LicenseClass {
    /// MIT / BSD / Apache-style — no copyleft obligations on your own code.
    Permissive,
    /// LGPL / MPL / EPL — file/library-level copyleft.
    WeakCopyleft,
    /// GPL / AGPL / SSPL — whole-program copyleft.
    StrongCopyleft,
    /// Proprietary, custom, or undetermined — needs a human look.
    Unknown,
}

impl LicenseClass {
    /// Restrictiveness rank for combining an AND expression (higher = stricter).
    fn rank(self) -> u8 {
        match self {
            LicenseClass::Permissive => 0,
            LicenseClass::WeakCopyleft => 1,
            LicenseClass::StrongCopyleft => 2,
            LicenseClass::Unknown => 3,
        }
    }
}

/// Where a component came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ComponentSource {
    /// The app's runtime/framework itself (Electron, Tauri, Qt, …).
    Runtime,
    /// A linked native library (OpenSSL, GnuTLS, …).
    NativeLibrary,
    /// A bundled npm dependency.
    Npm,
    /// An embedded Rust crate (cargo-auditable).
    Rust,
}

/// One licensed component of an application.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseComponent {
    pub name: String,
    pub version: Option<String>,
    /// The license expression as reported (SPDX where possible), or `"unknown"`.
    pub license: String,
    pub class: LicenseClass,
    pub source: ComponentSource,
    /// Extra context (e.g. "system component", "dual-licensed / commercial").
    pub note: Option<String>,
}

impl LicenseComponent {
    fn new(
        source: ComponentSource,
        name: impl Into<String>,
        version: Option<String>,
        license: &str,
    ) -> Self {
        let license = normalize_license(license);
        LicenseComponent {
            class: classify(&license),
            name: name.into(),
            version,
            license,
            source,
            note: None,
        }
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// A license value grouped across components, with its count.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseCount {
    pub license: String,
    pub class: LicenseClass,
    pub count: usize,
}

/// Component counts by copyleft class.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassTally {
    pub permissive: usize,
    pub weak_copyleft: usize,
    pub strong_copyleft: usize,
    pub unknown: usize,
}

/// The full license composition of an application.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseComposition {
    pub components: Vec<LicenseComponent>,
    /// Distinct licenses, most common first.
    pub by_license: Vec<LicenseCount>,
    pub tally: ClassTally,
    /// Paths (bundle-relative) of license/notice files the app ships.
    pub notice_files: Vec<String>,
    /// Human compliance flags (empty when nothing needs attention).
    pub flags: Vec<String>,
}

/// Normalize a raw license value to a tidy display string. Handles empty /
/// placeholder values and trims surrounding parens/whitespace.
pub fn normalize_license(raw: &str) -> String {
    let t = raw.trim().trim_matches(|c| c == '(' || c == ')').trim();
    if t.is_empty()
        || t.eq_ignore_ascii_case("unknown")
        || t.eq_ignore_ascii_case("unlicensed")
        || t.eq_ignore_ascii_case("see license in")
        || t.starts_with("SEE LICENSE")
        || t.starts_with("see license")
    {
        return "unknown".to_string();
    }
    t.to_string()
}

/// Classify a license expression (SPDX id or expression) by copyleft strength.
///
/// For an `OR` expression the least restrictive alternative wins (you may pick
/// it); for `AND` the most restrictive does. `WITH` exceptions and version
/// suffixes (`-only`, `-or-later`, trailing `+`) are folded onto the base id.
pub fn classify(expr: &str) -> LicenseClass {
    let expr = expr.trim();
    if expr.is_empty() || expr.eq_ignore_ascii_case("unknown") {
        return LicenseClass::Unknown;
    }

    let has_or = contains_op(expr, "OR");
    let ids: Vec<LicenseClass> = split_ids(expr).map(classify_id).collect();
    if ids.is_empty() {
        return LicenseClass::Unknown;
    }

    if has_or {
        // Least restrictive alternative — but only "fall through" to Unknown if
        // every alternative is Unknown.
        let known_min = ids
            .iter()
            .copied()
            .filter(|c| *c != LicenseClass::Unknown)
            .min_by_key(|c| c.rank());
        known_min.unwrap_or(LicenseClass::Unknown)
    } else {
        // AND (or a single id): most restrictive component.
        ids.into_iter().max_by_key(|c| c.rank()).unwrap()
    }
}

/// Whether `expr` contains the boolean operator `op` as a standalone token.
fn contains_op(expr: &str, op: &str) -> bool {
    expr.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .any(|tok| tok.eq_ignore_ascii_case(op))
}

/// Split an SPDX expression into bare license ids (dropping operators/parens/
/// `WITH` exceptions).
fn split_ids(expr: &str) -> impl Iterator<Item = &str> {
    expr.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|tok| {
            !tok.is_empty()
                && !tok.eq_ignore_ascii_case("OR")
                && !tok.eq_ignore_ascii_case("AND")
                && !tok.eq_ignore_ascii_case("WITH")
        })
        // After a `WITH`, the next token is an exception id — but for
        // classification the base license already decided the class, and
        // exception ids (LLVM-exception, Classpath-exception-2.0) won't match the
        // table, landing as Unknown; drop obvious exception tokens.
        .filter(|tok| !tok.to_ascii_lowercase().contains("exception"))
}

/// Classify a single SPDX license id (case-insensitive; suffixes folded).
fn classify_id(id: &str) -> LicenseClass {
    let base = fold_id(id);
    // Strong copyleft.
    const STRONG: &[&str] = &[
        "gpl-2.0", "gpl-3.0", "gpl-1.0", "agpl-3.0", "agpl-1.0", "sspl-1.0",
    ];
    // Weak / file-level copyleft.
    const WEAK: &[&str] = &[
        "lgpl-2.0", "lgpl-2.1", "lgpl-3.0", "mpl-1.0", "mpl-1.1", "mpl-2.0", "epl-1.0", "epl-2.0",
        "cddl-1.0", "cddl-1.1", "eupl-1.1", "eupl-1.2", "osl-3.0", "ms-rl", "cecill-2.1",
    ];
    // Permissive.
    const PERMISSIVE: &[&str] = &[
        "mit", "mit-0", "x11", "isc", "apache-2.0", "apache-1.1", "bsd-2-clause", "bsd-3-clause",
        "bsd-3-clause-clear", "bsd-4-clause", "0bsd", "bsd-0", "zlib", "libpng", "unlicense",
        "wtfpl", "bsl-1.0", "boost", "postgresql", "python-2.0", "psf-2.0", "cc0-1.0", "ncsa",
        "openssl", "ssleay", "ruby", "artistic-2.0", "zpl-2.1", "ofl-1.1", "beerware", "curl",
        "cc-by-4.0", "cc-by-3.0", "mpich2", "vim", "unicode-dfs-2016", "unicode-3.0", "blueoak-1.0.0",
    ];

    if PERMISSIVE.contains(&base.as_str()) {
        LicenseClass::Permissive
    } else if WEAK.contains(&base.as_str()) {
        LicenseClass::WeakCopyleft
    } else if STRONG.contains(&base.as_str()) {
        LicenseClass::StrongCopyleft
    } else {
        LicenseClass::Unknown
    }
}

/// Lowercase an id and drop `-only` / `-or-later` / trailing `+` so version
/// variants collapse onto the base id in the tables.
fn fold_id(id: &str) -> String {
    let mut s = id.trim().trim_end_matches('+').to_ascii_lowercase();
    for suf in ["-or-later", "-only"] {
        if let Some(stripped) = s.strip_suffix(suf) {
            s = stripped.to_string();
        }
    }
    s
}

/// Curated license for a detected runtime/framework (lowercased framework key,
/// matching `detect::Framework` serde). Returns `(license, note)`.
pub fn runtime_license(framework: &str) -> Option<(&'static str, Option<&'static str>)> {
    let v = match framework {
        "electron" => ("MIT", None),
        "chromium" | "chromiumbrowser" => ("BSD-3-Clause", Some("plus bundled third-party — see Chromium notices")),
        "cef" => ("BSD-3-Clause", None),
        "node" => ("MIT", None),
        "tauri" => ("MIT OR Apache-2.0", None),
        "deno" => ("MIT", None),
        "nwjs" => ("MIT", None),
        "flutter" => ("BSD-3-Clause", None),
        "qt" => ("LGPL-3.0-or-later", Some("open-source Qt is LGPLv3 / GPL; commercial license also available")),
        "reactnative" | "react_native" => ("MIT", None),
        "wails" => ("MIT", None),
        "sciter" => ("unknown", Some("proprietary engine — free/commercial licensing")),
        "java" => ("GPL-2.0-only WITH Classpath-exception-2.0", Some("OpenJDK — Classpath exception relaxes linking")),
        "safari" | "webkit" => ("LGPL-2.1-or-later AND BSD-2-Clause", Some("system WebKit component")),
        _ => return None,
    };
    Some(v)
}

/// Curated license for a known linked native library (by cbom library name).
pub fn native_library_license(name: &str) -> Option<(&'static str, Option<&'static str>)> {
    let v = match name {
        "OpenSSL" => ("Apache-2.0", None),
        "BoringSSL" => ("OpenSSL AND ISC", None),
        "LibreSSL" => ("OpenSSL AND ISC", None),
        "GnuTLS" => ("LGPL-2.1-or-later", None),
        "libgcrypt" => ("LGPL-2.1-or-later", None),
        "wolfSSL" => ("GPL-2.0-or-later", Some("dual-licensed — GPLv2 or commercial")),
        "libsodium" => ("ISC", None),
        "mbedTLS" => ("Apache-2.0", None),
        "nss" | "NSS" => ("MPL-2.0", None),
        "CommonCrypto" => ("unknown", Some("Apple system library")),
        _ => return None,
    };
    Some(v)
}

/// Build a runtime component from a detected framework + its version.
pub fn runtime_component(framework: &str, version: Option<String>) -> Option<LicenseComponent> {
    let (license, note) = runtime_license(framework)?;
    let mut c = LicenseComponent::new(ComponentSource::Runtime, framework, version, license);
    if let Some(n) = note {
        c = c.with_note(n);
    }
    Some(c)
}

/// Build a native-library component, if the library is a known one.
pub fn native_component(name: &str, version: Option<String>) -> Option<LicenseComponent> {
    let (license, note) = native_library_license(name)?;
    let mut c = LicenseComponent::new(ComponentSource::NativeLibrary, name, version, license);
    if let Some(n) = note {
        c = c.with_note(n);
    }
    Some(c)
}

/// Build an npm component from a dependency's reported license (may be empty).
pub fn npm_component(name: &str, version: Option<String>, license: &str) -> LicenseComponent {
    LicenseComponent::new(ComponentSource::Npm, name, version, license)
}

/// Build a Rust-crate component from a resolved license (may be empty).
pub fn rust_component(name: &str, version: Option<String>, license: &str) -> LicenseComponent {
    LicenseComponent::new(ComponentSource::Rust, name, version, license)
}

/// Aggregate components + discovered notice files into a full composition.
pub fn compose(mut components: Vec<LicenseComponent>, notice_files: Vec<String>) -> LicenseComposition {
    // Stable, readable order: by source, then name.
    components.sort_by(|a, b| {
        (a.source as u8, a.name.to_lowercase()).cmp(&(b.source as u8, b.name.to_lowercase()))
    });

    let mut tally = ClassTally::default();
    let mut counts: BTreeMap<String, (LicenseClass, usize)> = BTreeMap::new();
    for c in &components {
        match c.class {
            LicenseClass::Permissive => tally.permissive += 1,
            LicenseClass::WeakCopyleft => tally.weak_copyleft += 1,
            LicenseClass::StrongCopyleft => tally.strong_copyleft += 1,
            LicenseClass::Unknown => tally.unknown += 1,
        }
        let e = counts.entry(c.license.clone()).or_insert((c.class, 0));
        e.1 += 1;
    }

    let mut by_license: Vec<LicenseCount> = counts
        .into_iter()
        .map(|(license, (class, count))| LicenseCount { license, class, count })
        .collect();
    by_license.sort_by(|a, b| b.count.cmp(&a.count).then(a.license.cmp(&b.license)));

    let mut flags = Vec::new();
    if tally.strong_copyleft > 0 {
        flags.push(format!(
            "{} component(s) under strong copyleft (GPL/AGPL/SSPL) — review distribution obligations",
            tally.strong_copyleft
        ));
    }
    if tally.weak_copyleft > 0 {
        flags.push(format!(
            "{} component(s) under weak copyleft (LGPL/MPL/EPL) — dynamic-linking / file-level obligations",
            tally.weak_copyleft
        ));
    }
    if tally.unknown > 0 {
        flags.push(format!(
            "{} component(s) with undetermined or proprietary license — needs review",
            tally.unknown
        ));
    }

    LicenseComposition {
        components,
        by_license,
        tally,
        notice_files,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_basics() {
        assert_eq!(classify("MIT"), LicenseClass::Permissive);
        assert_eq!(classify("Apache-2.0"), LicenseClass::Permissive);
        assert_eq!(classify("LGPL-2.1-or-later"), LicenseClass::WeakCopyleft);
        assert_eq!(classify("GPL-3.0-only"), LicenseClass::StrongCopyleft);
        assert_eq!(classify("AGPL-3.0"), LicenseClass::StrongCopyleft);
        assert_eq!(classify("NOASSERTION"), LicenseClass::Unknown);
    }

    #[test]
    fn or_takes_least_restrictive() {
        // Dual license: pick the permissive branch.
        assert_eq!(classify("MIT OR Apache-2.0"), LicenseClass::Permissive);
        assert_eq!(classify("GPL-2.0-or-later OR MIT"), LicenseClass::Permissive);
        // WITH exception folds onto the base.
        assert_eq!(
            classify("GPL-2.0-only WITH Classpath-exception-2.0"),
            LicenseClass::StrongCopyleft
        );
    }

    #[test]
    fn and_takes_most_restrictive() {
        assert_eq!(classify("MIT AND GPL-3.0-only"), LicenseClass::StrongCopyleft);
        assert_eq!(classify("(MIT AND BSD-3-Clause)"), LicenseClass::Permissive);
    }

    #[test]
    fn normalize_placeholders() {
        assert_eq!(normalize_license(""), "unknown");
        assert_eq!(normalize_license("UNLICENSED"), "unknown");
        assert_eq!(normalize_license("  MIT  "), "MIT");
    }

    #[test]
    fn compose_tally_and_flags() {
        let comps = vec![
            npm_component("a", None, "MIT"),
            npm_component("b", None, "GPL-3.0-only"),
            npm_component("c", None, ""),
        ];
        let out = compose(comps, vec![]);
        assert_eq!(out.tally.permissive, 1);
        assert_eq!(out.tally.strong_copyleft, 1);
        assert_eq!(out.tally.unknown, 1);
        assert_eq!(out.flags.len(), 2); // strong + unknown
    }
}
