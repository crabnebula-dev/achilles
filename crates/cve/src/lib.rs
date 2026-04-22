//! Vulnerability lookup for detected runtimes and bundled npm dependencies.
//!
//! Data sources:
//!
//! | Runtime / target      | Source                                 |
//! |-----------------------|----------------------------------------|
//! | Electron              | OSV, ecosystem `npm`                   |
//! | Tauri                 | OSV, ecosystem `crates.io`             |
//! | Node.js core          | NVD, `cpe:2.3:a:nodejs:node.js:*`      |
//! | Chromium              | NVD, `cpe:2.3:a:google:chrome:*`       |
//! | Bundled npm deps      | OSV `v1/querybatch`, ecosystem `npm`   |
//!
//! All lookups are memoised on disk via [`crate::cache`] with a 24-hour TTL.

use reqwest::Client;
use serde::{Deserialize, Serialize};

pub use detect::Versions;

mod advisory;
mod cache;
mod settings;
mod sources;

pub use advisory::{severity_from_cvss, Advisory, Severity, Source};
pub use settings::{
    load as load_settings, save as save_settings, settings_path, EuvdSettings, FilterSettings,
    GhsaSettings, NvdSettings, OsvSettings, Settings, SourceSettings,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unexpected payload: {0}")]
    BadPayload(String),
}

/// Grouped advisories for a single app's detected runtimes.
///
/// Each field is a separate bucket so the UI can render present-but-empty
/// (runtime detected, no advisories) distinctly from absent (runtime not
/// detected at all).
#[derive(Debug, Clone, Default, Serialize)]
pub struct CveReport {
    pub electron: Vec<Advisory>,
    pub tauri: Vec<Advisory>,
    pub node: Vec<Advisory>,
    pub chromium: Vec<Advisory>,
    pub flutter: Vec<Advisory>,
    pub qt: Vec<Advisory>,
    pub nwjs: Vec<Advisory>,
    pub react_native: Vec<Advisory>,
    pub wails: Vec<Advisory>,
    pub sciter: Vec<Advisory>,
    pub java: Vec<Advisory>,
    /// Safari / system WKWebView advisories (looked up via
    /// `cpe:2.3:a:apple:safari:*`). Populated for Safari itself and for
    /// every WKWebView-backed app (Tauri, Wails) whose scan picked up the
    /// system Safari version.
    pub webkit: Vec<Advisory>,
    /// Per-source error messages encountered during this report. A single
    /// source failing never aborts the whole report — it just shows up here.
    pub errors: Vec<String>,
}

/// One npm dependency extracted from a bundle's `package.json` /
/// `package-lock.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackage {
    pub name: String,
    pub version: String,
}

/// Advisories matched against a single bundled npm dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackageAdvisories {
    pub package: NpmPackage,
    pub advisories: Vec<Advisory>,
}

/// HTTP + caching client. One per scan session; reqwest owns the connection
/// pool.
pub struct Client_ {
    http: Client,
    settings: Settings,
}

// `Client` is also a public type name on reqwest — we rename to avoid shadowing
// in user code while still keeping a short public name.
pub type OsvClient = Client_;

impl Default for Client_ {
    fn default() -> Self {
        Self::new()
    }
}

impl Client_ {
    pub fn new() -> Self {
        Self::with_settings(settings::load())
    }

    pub fn with_settings(settings: Settings) -> Self {
        let http = Client::builder()
            .user_agent(concat!(
                "achilles/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/crabnebula-dev/achilles)"
            ))
            .build()
            .expect("reqwest client builder");
        Self { http, settings }
    }

    /// Build a full [`CveReport`] for a set of detected versions. Each
    /// enabled source runs independently — a single failure goes into
    /// `errors` and the report still returns. Sources disabled in settings
    /// are skipped silently.
    pub async fn report_for(&self, versions: &Versions) -> CveReport {
        let mut report = CveReport::default();
        let s = &self.settings.sources;

        if let Some(v) = &versions.electron {
            if s.osv.enabled {
                match sources::osv::lookup(&self.http, "npm", "electron", v).await {
                    Ok(advisories) => report.electron.extend(advisories),
                    Err(err) => report.errors.push(format!("[osv] electron {v}: {err}")),
                }
            }
            if s.ghsa.enabled {
                match sources::ghsa::lookup(
                    &self.http,
                    s.ghsa.token.as_deref(),
                    "npm",
                    "electron",
                    v,
                )
                .await
                {
                    Ok(advisories) => report.electron.extend(advisories),
                    Err(err) => report.errors.push(format!("[ghsa] electron {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Electron", "Electron", v).await {
                    Ok(advisories) => report.electron.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] electron {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.tauri {
            if s.osv.enabled {
                match sources::osv::lookup(&self.http, "crates.io", "tauri", v).await {
                    Ok(advisories) => report.tauri.extend(advisories),
                    Err(err) => report.errors.push(format!("[osv] tauri {v}: {err}")),
                }
            }
            if s.ghsa.enabled {
                match sources::ghsa::lookup(
                    &self.http,
                    s.ghsa.token.as_deref(),
                    "rust",
                    "tauri",
                    v,
                )
                .await
                {
                    Ok(advisories) => report.tauri.extend(advisories),
                    Err(err) => report.errors.push(format!("[ghsa] tauri {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Tauri", "Tauri", v).await {
                    Ok(advisories) => report.tauri.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] tauri {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.node {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "nodejs",
                    "node.js",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.node.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] node {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Node.js", "Node.js", v).await {
                    Ok(advisories) => report.node.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] node {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.chromium {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "google",
                    "chrome",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.chromium.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] chromium {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Google", "Chrome", v).await {
                    Ok(advisories) => report.chromium.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] chromium {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.flutter {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "google",
                    "flutter",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.flutter.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] flutter {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Google", "Flutter", v).await {
                    Ok(advisories) => report.flutter.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] flutter {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.qt {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "qt",
                    "qt",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.qt.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] qt {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Qt", "Qt", v).await {
                    Ok(advisories) => report.qt.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] qt {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.nwjs {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "nwjs",
                    "nwjs",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.nwjs.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] nwjs {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "nwjs", "NW.js", v).await {
                    Ok(advisories) => report.nwjs.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] nwjs {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.react_native {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "facebook",
                    "react_native",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.react_native.extend(advisories),
                    Err(err) => report
                        .errors
                        .push(format!("[nvd] react-native {v}: {err}")),
                }
            }
            if s.osv.enabled {
                match sources::osv::lookup(&self.http, "npm", "react-native", v).await {
                    Ok(advisories) => report.react_native.extend(advisories),
                    Err(err) => report
                        .errors
                        .push(format!("[osv] react-native {v}: {err}")),
                }
            }
            if s.ghsa.enabled {
                match sources::ghsa::lookup(
                    &self.http,
                    s.ghsa.token.as_deref(),
                    "npm",
                    "react-native",
                    v,
                )
                .await
                {
                    Ok(advisories) => report.react_native.extend(advisories),
                    Err(err) => report
                        .errors
                        .push(format!("[ghsa] react-native {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.wails {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "wailsapp",
                    "wails",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.wails.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] wails {v}: {err}")),
                }
            }
            if s.ghsa.enabled {
                match sources::ghsa::lookup(
                    &self.http,
                    s.ghsa.token.as_deref(),
                    "go",
                    "github.com/wailsapp/wails/v2",
                    v,
                )
                .await
                {
                    Ok(advisories) => report.wails.extend(advisories),
                    Err(err) => report.errors.push(format!("[ghsa] wails {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.sciter {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "terrainformatica",
                    "sciter",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.sciter.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] sciter {v}: {err}")),
                }
            }
        }

        // … runtime lookups follow …
        // (post-processing filter runs at the bottom of this function)

        if let Some(v) = &versions.webkit {
            if s.nvd.enabled {
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "apple",
                    "safari",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.webkit.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] webkit {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Apple", "Safari", v).await {
                    Ok(advisories) => report.webkit.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] webkit {v}: {err}")),
                }
            }
        }

        if let Some(v) = &versions.java {
            if s.nvd.enabled {
                // Oracle JDK is the canonical CPE; OpenJDK advisories are
                // typically echoed there because they share a codebase.
                // Vendor-specific CPEs (redhat:openjdk, eclipse:temurin, …)
                // are a follow-up once we parse IMPLEMENTOR from the JRE
                // `release` file.
                match sources::nvd::lookup_cpe_with_key(
                    &self.http,
                    "oracle",
                    "jdk",
                    v,
                    s.nvd.api_key.as_deref(),
                )
                .await
                {
                    Ok(advisories) => report.java.extend(advisories),
                    Err(err) => report.errors.push(format!("[nvd] java {v}: {err}")),
                }
            }
            if s.euvd.enabled {
                match sources::euvd::lookup(&self.http, "Oracle", "JDK", v).await {
                    Ok(advisories) => report.java.extend(advisories),
                    Err(err) => report.errors.push(format!("[euvd] java {v}: {err}")),
                }
            }
        }

        apply_age_filter(&mut report, self.settings.filters.max_age_years);
        report
    }

    /// Run a raw OSV query (handy for the example CLI / tests).
    pub async fn query(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<Advisory>, Error> {
        sources::osv::lookup(&self.http, ecosystem, name, version).await
    }

    /// Batch-check a list of bundled npm packages against OSV. Preserves input
    /// order; empty advisories lists mean "no known CVE for that version."
    pub async fn batch_npm(
        &self,
        deps: &[NpmPackage],
    ) -> Result<Vec<NpmPackageAdvisories>, Error> {
        sources::osv::batch_npm(&self.http, deps).await
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }
}

// ---------- filtering ----------------------------------------------------

/// Strip advisories older than `max_age_years` years. `None` is a no-op.
///
/// Advisories with no parseable `published` date are *kept* — better to
/// show a non-dated advisory than to silently drop a possibly-relevant one.
fn apply_age_filter(report: &mut CveReport, max_age_years: Option<u32>) {
    let Some(max) = max_age_years else {
        return;
    };
    let Some(current) = current_year() else {
        return;
    };
    let cutoff = current.saturating_sub(max);

    let filter = |v: &mut Vec<Advisory>| {
        v.retain(|a| advisory_year(a).map_or(true, |y| y >= cutoff));
    };

    filter(&mut report.electron);
    filter(&mut report.tauri);
    filter(&mut report.node);
    filter(&mut report.chromium);
    filter(&mut report.flutter);
    filter(&mut report.qt);
    filter(&mut report.nwjs);
    filter(&mut report.react_native);
    filter(&mut report.wails);
    filter(&mut report.sciter);
    filter(&mut report.java);
    filter(&mut report.webkit);
}

/// Same filter applied to npm-dep advisory lists from [`Client_::batch_npm`].
pub fn filter_npm_by_age(
    results: &mut [NpmPackageAdvisories],
    max_age_years: Option<u32>,
) {
    let Some(max) = max_age_years else {
        return;
    };
    let Some(current) = current_year() else {
        return;
    };
    let cutoff = current.saturating_sub(max);
    for r in results.iter_mut() {
        r.advisories
            .retain(|a| advisory_year(a).map_or(true, |y| y >= cutoff));
    }
}

fn advisory_year(advisory: &Advisory) -> Option<u32> {
    advisory
        .published
        .as_deref()
        .and_then(|s| s.get(..4))
        .and_then(|yr| yr.parse().ok())
}

/// Current Gregorian year from `SystemTime::now()`. Hand-rolled to avoid
/// pulling in `chrono`.
fn current_year() -> Option<u32> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let days = (secs / 86_400) as i64;
    let mut year = 1970u32;
    let mut remaining = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let in_year = if leap { 366 } else { 365 };
        if remaining < in_year {
            return Some(year);
        }
        remaining -= in_year;
        year += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(year: Option<&str>) -> Advisory {
        Advisory {
            id: "TEST".into(),
            source: Source::Nvd,
            summary: String::new(),
            severity: None,
            fixed_in: None,
            aliases: vec![],
            published: year.map(|y| format!("{y}-01-01T00:00:00Z")),
            references: vec![],
        }
    }

    #[test]
    fn filter_drops_old_keeps_new_and_undated() {
        let mut report = CveReport {
            chromium: vec![
                adv(Some("1999")),
                adv(Some("2023")),
                adv(None),
                adv(Some("2026")),
            ],
            ..Default::default()
        };
        // Cutoff: 2026 - 3 = 2023 ⇒ keep ≥ 2023 and undated.
        apply_age_filter(&mut report, Some(3));
        assert_eq!(report.chromium.len(), 3);
        assert!(report
            .chromium
            .iter()
            .any(|a| a.published.as_deref() == Some("2023-01-01T00:00:00Z")));
        assert!(report.chromium.iter().any(|a| a.published.is_none()));
    }

    #[test]
    fn filter_disabled_keeps_all() {
        let mut report = CveReport {
            chromium: vec![adv(Some("1990")), adv(Some("2000"))],
            ..Default::default()
        };
        apply_age_filter(&mut report, None);
        assert_eq!(report.chromium.len(), 2);
    }
}
