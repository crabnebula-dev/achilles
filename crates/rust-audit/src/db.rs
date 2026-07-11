//! The RustSec advisory database — <https://github.com/RustSec/advisory-db>.
//!
//! Cloned/updated with `git` into the app cache; advisories live at
//! `crates/<name>/RUSTSEC-YYYY-NNNN.toml`. We only read the advisories for the
//! crates a binary actually contains, and match versions with `semver`.

use std::path::PathBuf;
use std::process::Command;

use semver::{Version, VersionReq};
use serde::Deserialize;

const ADVISORY_DB_URL: &str = "https://github.com/RustSec/advisory-db.git";

pub struct Database {
    root: PathBuf,
}

/// A single RustSec advisory (the fields we surface).
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub aliases: Vec<String>,
    pub cvss: Option<String>,
    /// Non-`None` for informational advisories (`unmaintained`, `unsound`, …).
    pub informational: Option<String>,
    pub url: Option<String>,
    /// Raw semver requirements (kept as strings for display).
    pub patched: Vec<String>,
    pub unaffected: Vec<String>,
}

impl Advisory {
    /// Whether `version` is affected: not covered by any `patched` or
    /// `unaffected` requirement.
    pub fn affects(&self, version: &Version) -> bool {
        let matches_any = |reqs: &[String]| {
            reqs.iter()
                .filter_map(|s| VersionReq::parse(s).ok())
                .any(|req| req.matches(version))
        };
        !matches_any(&self.patched) && !matches_any(&self.unaffected)
    }
}

#[derive(Deserialize)]
struct RawFile {
    advisory: RawMeta,
    #[serde(default)]
    versions: RawVersions,
}

#[derive(Deserialize)]
struct RawMeta {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    cvss: Option<String>,
    #[serde(default)]
    informational: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawVersions {
    #[serde(default)]
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}

impl Database {
    /// Local cache path for the advisory-db.
    pub fn cache_path() -> Option<PathBuf> {
        Some(dirs::cache_dir()?.join("achilles").join("advisory-db"))
    }

    /// Ensure a local clone exists (cloning, or pulling if older than a day).
    pub fn ensure() -> Result<Self, String> {
        let root = Self::cache_path().ok_or("no cache directory")?;
        if root.join(".git").is_dir() {
            let stale = std::fs::metadata(&root)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|e| e.as_secs() > 86_400)
                .unwrap_or(true);
            if stale {
                // Best-effort refresh; stale data is better than none.
                let _ = git(&["-C", path_str(&root)?, "pull", "--ff-only"]);
            }
        } else {
            if let Some(parent) = root.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            git(&["clone", "--depth", "1", ADVISORY_DB_URL, path_str(&root)?])?;
        }
        Ok(Self { root })
    }

    /// Advisories filed against `crate_name`.
    pub fn advisories_for(&self, crate_name: &str) -> Vec<Advisory> {
        let dir = self.root.join("crates").join(crate_name);
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(raw) = toml::from_str::<RawFile>(&text) else {
                continue;
            };
            out.push(Advisory {
                id: raw.advisory.id,
                title: raw.advisory.title,
                aliases: raw.advisory.aliases,
                cvss: raw.advisory.cvss,
                informational: raw.advisory.informational,
                url: raw.advisory.url,
                patched: raw.versions.patched,
                unaffected: raw.versions.unaffected,
            });
        }
        out
    }
}

fn path_str(p: &std::path::Path) -> Result<&str, String> {
    p.to_str().ok_or_else(|| "non-UTF-8 path".to_string())
}

fn git(args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("git not available: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("git command failed")
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(patched: &[&str], unaffected: &[&str]) -> Advisory {
        Advisory {
            id: "RUSTSEC-2024-0001".into(),
            title: "test".into(),
            aliases: vec![],
            cvss: None,
            informational: None,
            url: None,
            patched: patched.iter().map(|s| s.to_string()).collect(),
            unaffected: unaffected.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn version_matching() {
        let a = adv(&[">= 1.2.3"], &["< 1.0.0"]);
        assert!(a.affects(&Version::parse("1.2.0").unwrap())); // between unaffected and patched
        assert!(!a.affects(&Version::parse("1.2.3").unwrap())); // patched
        assert!(!a.affects(&Version::parse("1.5.0").unwrap())); // patched
        assert!(!a.affects(&Version::parse("0.9.0").unwrap())); // unaffected

        // No bounds → affects everything (e.g. informational advisories).
        let open = adv(&[], &[]);
        assert!(open.affects(&Version::parse("9.9.9").unwrap()));
    }
}
