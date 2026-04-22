//! Extract bundled npm dependency lists from an ASAR or source directory.
//!
//! We prefer `package-lock.json` (authoritative, includes transitive deps)
//! but fall back to `package.json` (top-level only, versions may be ranges).
//!
//! Output is deduplicated by `(name, version)` so a single package that
//! appears in multiple places in the lockfile only reports once.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One npm dependency extracted from a bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub source: DependencySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencySource {
    /// Parsed from a `package-lock.json` — concrete transitive dep graph.
    PackageLock,
    /// Parsed from a `package.json` — top-level declarations only.
    PackageJson,
}

/// Pull dependencies out of byte buffers representing `package-lock.json`
/// and/or `package.json`. Either may be `None`. Returns a sorted,
/// deduplicated list.
pub fn parse(
    package_lock: Option<&[u8]>,
    package_json: Option<&[u8]>,
) -> Vec<Dependency> {
    let mut set: BTreeSet<Dependency> = BTreeSet::new();

    if let Some(bytes) = package_lock {
        parse_package_lock(bytes, &mut set);
    }
    // Only bother with package.json if we didn't extract anything from lock.
    if set.is_empty() {
        if let Some(bytes) = package_json {
            parse_package_json(bytes, &mut set);
        }
    }

    set.into_iter().collect()
}

fn parse_package_lock(bytes: &[u8], out: &mut BTreeSet<Dependency>) {
    let Ok(root): Result<serde_json::Value, _> = serde_json::from_slice(bytes) else {
        return;
    };

    // npm 7+ (lockfileVersion 2/3): the canonical tree lives in
    //   root.packages = { "<path>": { "name": "...", "version": "...", ... } }
    // where the empty path key is the project itself (skip it). For all
    // other entries, `name` is either present or derivable from the key.
    if let Some(packages) = root.get("packages").and_then(|v| v.as_object()) {
        for (path, entry) in packages {
            if path.is_empty() {
                continue; // root project itself
            }
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| derive_name_from_path(path));
            if name.is_empty() {
                continue;
            }
            out.insert(Dependency {
                name,
                version: version.to_owned(),
                source: DependencySource::PackageLock,
            });
        }
        return;
    }

    // npm 6 (lockfileVersion 1): nested "dependencies" tree.
    if let Some(deps) = root.get("dependencies").and_then(|v| v.as_object()) {
        walk_v1_deps(deps, out);
    }
}

fn walk_v1_deps(deps: &serde_json::Map<String, serde_json::Value>, out: &mut BTreeSet<Dependency>) {
    for (name, entry) in deps {
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            out.insert(Dependency {
                name: name.clone(),
                version: version.to_owned(),
                source: DependencySource::PackageLock,
            });
        }
        if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
            walk_v1_deps(nested, out);
        }
    }
}

fn parse_package_json(bytes: &[u8], out: &mut BTreeSet<Dependency>) {
    let Ok(root): Result<serde_json::Value, _> = serde_json::from_slice(bytes) else {
        return;
    };
    for section in &[
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(block) = root.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, version) in block {
            let Some(version) = version.as_str() else {
                continue;
            };
            let cleaned = clean_pkg_json_range(version);
            if cleaned.is_empty() {
                continue;
            }
            out.insert(Dependency {
                name: name.clone(),
                version: cleaned,
                source: DependencySource::PackageJson,
            });
        }
    }
}

/// `package.json` versions are ranges (`^1.2.3`, `~2.0`, `*`, git URLs, …).
/// OSV wants a concrete version. We strip common npm range prefixes and
/// skip non-semver values. This is coarse on purpose — lock files are the
/// authoritative source; package.json is a fallback.
fn clean_pkg_json_range(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.contains(':') || trimmed.contains('/') || trimmed.is_empty() || trimmed == "*" {
        // git/file/npm-alias specs, or wildcard — skip.
        return String::new();
    }
    let stripped = trimmed
        .trim_start_matches(|c: char| matches!(c, '^' | '~' | '=' | '>' | '<' | 'v' | ' '));
    stripped.split_whitespace().next().unwrap_or("").to_owned()
}

fn derive_name_from_path(path: &str) -> String {
    // The packages-key path is typically `node_modules/foo` or
    // `node_modules/@scope/bar`, possibly repeated (`node_modules/foo/node_modules/…`).
    // Take everything after the *last* `node_modules/` segment.
    let tail = path.rsplit_once("node_modules/").map(|(_, t)| t).unwrap_or(path);
    tail.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lockfile_v3() {
        let lock = br#"{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/foo": { "version": "1.2.3" },
                "node_modules/@scope/bar": { "version": "4.5.6" }
            }
        }"#;
        let deps = parse(Some(lock), None);
        assert!(deps.iter().any(|d| d.name == "foo" && d.version == "1.2.3"));
        assert!(deps.iter().any(|d| d.name == "@scope/bar" && d.version == "4.5.6"));
        assert!(!deps.iter().any(|d| d.name == "app"));
    }

    #[test]
    fn parses_lockfile_v1_nested() {
        let lock = br#"{
            "name": "app",
            "lockfileVersion": 1,
            "dependencies": {
                "foo": { "version": "1.0.0",
                    "dependencies": {
                        "bar": { "version": "2.0.0" }
                    }
                }
            }
        }"#;
        let deps = parse(Some(lock), None);
        assert!(deps.iter().any(|d| d.name == "foo" && d.version == "1.0.0"));
        assert!(deps.iter().any(|d| d.name == "bar" && d.version == "2.0.0"));
    }

    #[test]
    fn falls_back_to_package_json() {
        let pj = br#"{
            "name": "app",
            "dependencies": { "lodash": "^4.17.21", "git-dep": "git+https://foo/bar.git" },
            "devDependencies": { "typescript": "~5.2.0" }
        }"#;
        let deps = parse(None, Some(pj));
        assert!(deps.iter().any(|d| d.name == "lodash" && d.version == "4.17.21"));
        assert!(deps.iter().any(|d| d.name == "typescript" && d.version == "5.2.0"));
        // git dep should have been skipped
        assert!(!deps.iter().any(|d| d.name == "git-dep"));
    }

    #[test]
    fn lock_wins_over_package_json() {
        let lock = br#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/foo":{"version":"9.9.9"}}}"#;
        let pj = br#"{"dependencies":{"foo":"^1.0.0"}}"#;
        let deps = parse(Some(lock), Some(pj));
        // We should only see the lockfile version.
        assert_eq!(deps.iter().filter(|d| d.name == "foo").count(), 1);
        assert!(deps.iter().any(|d| d.name == "foo" && d.version == "9.9.9"));
    }
}
