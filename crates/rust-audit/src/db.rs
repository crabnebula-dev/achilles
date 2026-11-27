//! The RustSec advisory database — <https://github.com/RustSec/advisory-db>.
//!
//! Cloned/updated with `git` into the app cache; advisories live at
//! `crates/<name>/RUSTSEC-YYYY-NNNN.md` in the database's V3 format: a leading
//! ```` ```toml ```` fence holding the `[advisory]` / `[versions]` tables,
//! then a `# title` heading and Markdown prose. We only read the advisories
//! for the crates a binary actually contains, and match versions with
//! `semver`. Withdrawn advisories are skipped.

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
    aliases: Vec<String>,
    #[serde(default)]
    cvss: Option<String>,
    #[serde(default)]
    informational: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
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
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(advisory) = parse_advisory(&text) {
                out.push(advisory);
            }
        }
        out
    }
}

/// Parse one V3 advisory file: TOML inside a leading ```` ```toml ```` fence,
/// title as the first `# ` heading after it. Returns `None` for files that
/// don't match the layout, don't parse, or are withdrawn.
fn parse_advisory(text: &str) -> Option<Advisory> {
    let (toml_src, body) = split_toml_fence(text)?;
    let raw = toml::from_str::<RawFile>(toml_src).ok()?;
    if raw.advisory.withdrawn.is_some() {
        return None;
    }
    Some(Advisory {
        id: raw.advisory.id,
        title: heading_title(body).unwrap_or_default(),
        aliases: raw.advisory.aliases,
        cvss: raw.advisory.cvss,
        informational: raw.advisory.informational,
        url: raw.advisory.url,
        patched: raw.versions.patched,
        unaffected: raw.versions.unaffected,
    })
}

/// Split a V3 advisory into (TOML inside the opening ```` ```toml ```` fence,
/// everything after the closing fence). `None` if the file doesn't start with
/// such a fence.
fn split_toml_fence(text: &str) -> Option<(&str, &str)> {
    const FENCE_OPEN: &str = "```toml";
    const FENCE_CLOSE: &str = "\n```";

    let rest = text.strip_prefix(FENCE_OPEN)?;
    let rest = rest
        .strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))?;
    let close = rest.find(FENCE_CLOSE)?;
    // On a CRLF checkout the line before the fence ends in `\r`, which TOML
    // rejects as a stray character.
    let toml_src = rest[..close].trim_end_matches('\r');
    let body = rest[close + FENCE_CLOSE.len()..].trim_start_matches(['\r', '\n']);
    Some((toml_src, body))
}

/// The first Markdown `# ` heading in `body`, trimmed.
fn heading_title(body: &str) -> Option<String> {
    body.lines()
        .map(str::trim_end)
        .find_map(|l| l.strip_prefix("# "))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
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

    // Real advisories copied verbatim from RustSec/advisory-db (CC0).
    const SMALLVEC: &str = include_str!("../test-data/RUSTSEC-2021-0003.md");
    const ADLER_UNMAINTAINED: &str = include_str!("../test-data/RUSTSEC-2025-0056.md");
    const GIT2_WITHDRAWN: &str = include_str!("../test-data/RUSTSEC-2023-0002.md");

    #[test]
    fn parses_a_v3_vulnerability_advisory() {
        let a = parse_advisory(SMALLVEC).expect("parses");
        assert_eq!(a.id, "RUSTSEC-2021-0003");
        // The title is the Markdown heading, not a TOML key.
        assert_eq!(a.title, "Buffer overflow in SmallVec::insert_many");
        assert_eq!(a.aliases, ["CVE-2021-25900", "GHSA-43w2-9j62-hq99"]);
        assert_eq!(
            a.cvss.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        assert_eq!(a.informational, None);
        assert_eq!(a.patched, [">= 0.6.14, < 1.0.0", ">= 1.6.1"]);
        assert_eq!(a.unaffected, ["< 0.6.3"]);
        assert!(a.affects(&Version::parse("1.6.0").unwrap()));
        assert!(!a.affects(&Version::parse("1.6.1").unwrap()));
        assert!(!a.affects(&Version::parse("0.6.2").unwrap()));
    }

    #[test]
    fn parses_an_informational_advisory_without_a_versions_table() {
        let a = parse_advisory(ADLER_UNMAINTAINED).expect("parses");
        assert_eq!(a.id, "RUSTSEC-2025-0056");
        assert_eq!(a.informational.as_deref(), Some("unmaintained"));
        assert!(a.patched.is_empty() && a.unaffected.is_empty());
        assert!(a.affects(&Version::parse("1.0.2").unwrap()));
    }

    #[test]
    fn withdrawn_advisories_are_skipped() {
        assert!(GIT2_WITHDRAWN.contains("withdrawn = "));
        assert!(parse_advisory(GIT2_WITHDRAWN).is_none());
    }

    #[test]
    fn crlf_checkout_parses_identically() {
        assert!(!SMALLVEC.contains('\r'));
        let crlf = SMALLVEC.replace('\n', "\r\n");
        let a = parse_advisory(&crlf).expect("parses with CRLF line endings");
        let b = parse_advisory(SMALLVEC).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.title, b.title);
        assert_eq!(a.patched, b.patched);
        assert_eq!(a.unaffected, b.unaffected);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_advisory("# just a heading\n").is_none());
        assert!(parse_advisory("```toml\nnot = [valid\n```\n# x\n").is_none());
        // Bare TOML without the fence is not a V3 advisory.
        assert!(parse_advisory("[advisory]\nid = \"RUSTSEC-2000-0001\"\n").is_none());
        assert!(parse_advisory("").is_none());
    }

    #[test]
    fn advisories_for_reads_md_files_and_drops_withdrawn() {
        let root = std::env::temp_dir().join(format!(
            "rust-audit-db-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let dir = root.join("crates").join("sample");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("RUSTSEC-2021-0003.md"), SMALLVEC).unwrap();
        std::fs::write(dir.join("RUSTSEC-2025-0056.md"), ADLER_UNMAINTAINED).unwrap();
        std::fs::write(dir.join("RUSTSEC-2023-0002.md"), GIT2_WITHDRAWN).unwrap();
        std::fs::write(dir.join("README.txt"), "ignored").unwrap();

        let db = Database { root: root.clone() };
        let mut ids: Vec<String> = db
            .advisories_for("sample")
            .into_iter()
            .map(|a| a.id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["RUSTSEC-2021-0003", "RUSTSEC-2025-0056"]);
        assert!(db.advisories_for("missing-crate").is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }
}
