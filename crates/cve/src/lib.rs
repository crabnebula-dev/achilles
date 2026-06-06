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
mod version;

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

/// Which [`CveReport`] field a concurrent lookup feeds into.
#[derive(Debug, Clone, Copy)]
enum Bucket {
    Electron,
    Tauri,
    Node,
    Chromium,
    Flutter,
    Qt,
    Nwjs,
    ReactNative,
    Wails,
    Sciter,
    Java,
    Webkit,
}

impl CveReport {
    fn bucket_mut(&mut self, bucket: Bucket) -> &mut Vec<Advisory> {
        match bucket {
            Bucket::Electron => &mut self.electron,
            Bucket::Tauri => &mut self.tauri,
            Bucket::Node => &mut self.node,
            Bucket::Chromium => &mut self.chromium,
            Bucket::Flutter => &mut self.flutter,
            Bucket::Qt => &mut self.qt,
            Bucket::Nwjs => &mut self.nwjs,
            Bucket::ReactNative => &mut self.react_native,
            Bucket::Wails => &mut self.wails,
            Bucket::Sciter => &mut self.sciter,
            Bucket::Java => &mut self.java,
            Bucket::Webkit => &mut self.webkit,
        }
    }
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
        use futures::future::{join_all, BoxFuture};

        let mut report = CveReport::default();
        let s = &self.settings.sources;
        let http = &self.http;

        // One lookup future per (runtime, source). They're independent network
        // calls, so we run them all concurrently rather than awaiting each in
        // turn — a multi-runtime Electron app would otherwise pay for a dozen
        // serialised round-trips (with NVD rate-limited on top). `join_all`
        // preserves order, so advisories land in each bucket as before.
        #[allow(clippy::type_complexity)]
        let mut tasks: Vec<BoxFuture<'_, (Bucket, String, Result<Vec<Advisory>, Error>)>> =
            Vec::new();

        macro_rules! task {
            ($bucket:expr, $src:literal, $name:literal, $v:expr, $fut:expr) => {{
                let prefix = format!("[{}] {} {}", $src, $name, $v);
                tasks.push(Box::pin(async move { ($bucket, prefix, $fut.await) }));
            }};
        }

        if let Some(v) = &versions.electron {
            if s.osv.enabled {
                task!(
                    Bucket::Electron,
                    "osv",
                    "electron",
                    v,
                    sources::osv::lookup(http, "npm", "electron", v)
                );
            }
            if s.ghsa.enabled {
                task!(
                    Bucket::Electron,
                    "ghsa",
                    "electron",
                    v,
                    sources::ghsa::lookup(http, s.ghsa.token.as_deref(), "npm", "electron", v)
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Electron,
                    "euvd",
                    "electron",
                    v,
                    sources::euvd::lookup(http, "Electron", "Electron", v)
                );
            }
        }

        if let Some(v) = &versions.tauri {
            if s.osv.enabled {
                task!(
                    Bucket::Tauri,
                    "osv",
                    "tauri",
                    v,
                    sources::osv::lookup(http, "crates.io", "tauri", v)
                );
            }
            if s.ghsa.enabled {
                task!(
                    Bucket::Tauri,
                    "ghsa",
                    "tauri",
                    v,
                    sources::ghsa::lookup(http, s.ghsa.token.as_deref(), "rust", "tauri", v)
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Tauri,
                    "euvd",
                    "tauri",
                    v,
                    sources::euvd::lookup(http, "Tauri", "Tauri", v)
                );
            }
        }

        if let Some(v) = &versions.node {
            if s.nvd.enabled {
                task!(
                    Bucket::Node,
                    "nvd",
                    "node",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "nodejs",
                        "node.js",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Node,
                    "euvd",
                    "node",
                    v,
                    sources::euvd::lookup(http, "Node.js", "Node.js", v)
                );
            }
        }

        if let Some(v) = &versions.chromium {
            if s.nvd.enabled {
                task!(
                    Bucket::Chromium,
                    "nvd",
                    "chromium",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "google",
                        "chrome",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Chromium,
                    "euvd",
                    "chromium",
                    v,
                    sources::euvd::lookup(http, "Google", "Chrome", v)
                );
            }
        }

        if let Some(v) = &versions.flutter {
            if s.nvd.enabled {
                task!(
                    Bucket::Flutter,
                    "nvd",
                    "flutter",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "google",
                        "flutter",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Flutter,
                    "euvd",
                    "flutter",
                    v,
                    sources::euvd::lookup(http, "Google", "Flutter", v)
                );
            }
        }

        if let Some(v) = &versions.qt {
            if s.nvd.enabled {
                task!(
                    Bucket::Qt,
                    "nvd",
                    "qt",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "qt",
                        "qt",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Qt,
                    "euvd",
                    "qt",
                    v,
                    sources::euvd::lookup(http, "Qt", "Qt", v)
                );
            }
        }

        if let Some(v) = &versions.nwjs {
            if s.nvd.enabled {
                task!(
                    Bucket::Nwjs,
                    "nvd",
                    "nwjs",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "nwjs",
                        "nwjs",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Nwjs,
                    "euvd",
                    "nwjs",
                    v,
                    sources::euvd::lookup(http, "nwjs", "NW.js", v)
                );
            }
        }

        if let Some(v) = &versions.react_native {
            if s.nvd.enabled {
                task!(
                    Bucket::ReactNative,
                    "nvd",
                    "react-native",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "facebook",
                        "react_native",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.osv.enabled {
                task!(
                    Bucket::ReactNative,
                    "osv",
                    "react-native",
                    v,
                    sources::osv::lookup(http, "npm", "react-native", v)
                );
            }
            if s.ghsa.enabled {
                task!(
                    Bucket::ReactNative,
                    "ghsa",
                    "react-native",
                    v,
                    sources::ghsa::lookup(http, s.ghsa.token.as_deref(), "npm", "react-native", v)
                );
            }
        }

        if let Some(v) = &versions.wails {
            if s.nvd.enabled {
                task!(
                    Bucket::Wails,
                    "nvd",
                    "wails",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "wailsapp",
                        "wails",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.ghsa.enabled {
                task!(
                    Bucket::Wails,
                    "ghsa",
                    "wails",
                    v,
                    sources::ghsa::lookup(
                        http,
                        s.ghsa.token.as_deref(),
                        "go",
                        "github.com/wailsapp/wails/v2",
                        v
                    )
                );
            }
        }

        if let Some(v) = &versions.sciter {
            if s.nvd.enabled {
                task!(
                    Bucket::Sciter,
                    "nvd",
                    "sciter",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "terrainformatica",
                        "sciter",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
        }

        if let Some(v) = &versions.webkit {
            if s.nvd.enabled {
                task!(
                    Bucket::Webkit,
                    "nvd",
                    "webkit",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "apple",
                        "safari",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Webkit,
                    "euvd",
                    "webkit",
                    v,
                    sources::euvd::lookup(http, "Apple", "Safari", v)
                );
            }
        }

        if let Some(v) = &versions.java {
            if s.nvd.enabled {
                // Oracle JDK is the canonical CPE; OpenJDK advisories are
                // typically echoed there because they share a codebase.
                task!(
                    Bucket::Java,
                    "nvd",
                    "java",
                    v,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "oracle",
                        "jdk",
                        v,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Java,
                    "euvd",
                    "java",
                    v,
                    sources::euvd::lookup(http, "Oracle", "JDK", v)
                );
            }
        }

        for (bucket, prefix, result) in join_all(tasks).await {
            match result {
                Ok(advisories) => report.bucket_mut(bucket).extend(advisories),
                Err(err) => report.errors.push(format!("{prefix}: {err}")),
            }
        }

        apply_relevance_filter(&mut report, versions);
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
    pub async fn batch_npm(&self, deps: &[NpmPackage]) -> Result<Vec<NpmPackageAdvisories>, Error> {
        sources::osv::batch_npm(&self.http, deps).await
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }
}

// ---------- filtering ----------------------------------------------------

/// Drop advisories that don't actually apply to the scanned build:
///
///   * **already patched** — the advisory names a fix ceiling (via NVD's
///     `fixed_in`, or "prior to X" / "before X" in the description) that the
///     scanned version is at or past. This is what stops a runtime from being
///     flagged by the very CVE whose fix it already ships, and it covers
///     sources like EUVD that do only a coarse substring version match.
///   * **wrong platform** — the advisory is explicitly scoped to a different
///     OS ("on Android" while we audit macOS).
///
/// Conservative by construction: an advisory is kept whenever the version
/// can't be parsed or no clear ceiling/scope is stated.
fn apply_relevance_filter(report: &mut CveReport, versions: &Versions) {
    let os = version::current_os();

    // `product` is the marketing name a source's prose uses for the runtime.
    // We only set it for Safari, where Apple's "fixed in Safari 26.5, iOS
    // 18.7.9 …" lists pair each product with its *fixed* version. Elsewhere a
    // product-adjacent number can be an *affected* version, so we leave it
    // `None` and rely on the fix-semantic ceiling phrases ("prior to", …).
    let filter =
        |advisories: &mut Vec<Advisory>, scanned: Option<&String>, product: Option<&str>| {
            advisories.retain(|a| is_relevant(a, scanned, product, os));
        };

    filter(&mut report.electron, versions.electron.as_ref(), None);
    filter(&mut report.tauri, versions.tauri.as_ref(), None);
    filter(&mut report.node, versions.node.as_ref(), None);
    filter(&mut report.chromium, versions.chromium.as_ref(), None);
    filter(&mut report.flutter, versions.flutter.as_ref(), None);
    filter(&mut report.qt, versions.qt.as_ref(), None);
    filter(&mut report.nwjs, versions.nwjs.as_ref(), None);
    filter(
        &mut report.react_native,
        versions.react_native.as_ref(),
        None,
    );
    filter(&mut report.wails, versions.wails.as_ref(), None);
    filter(&mut report.sciter, versions.sciter.as_ref(), None);
    filter(&mut report.java, versions.java.as_ref(), None);
    filter(&mut report.webkit, versions.webkit.as_ref(), Some("Safari"));
}

/// Decide whether a single advisory applies to `scanned` version on `os`.
fn is_relevant(
    advisory: &Advisory,
    scanned: Option<&String>,
    product: Option<&str>,
    os: version::Os,
) -> bool {
    if version::scoped_to_other_os(&advisory.summary, os) {
        return false;
    }
    let Some(scanned) = scanned else {
        return true; // no version to compare against — keep
    };
    // A fix ceiling can come from the structured `fixed_in` field or from the
    // prose. If the scanned build is at or past it, the build is patched.
    let ceiling = advisory
        .fixed_in
        .clone()
        .or_else(|| version::fixed_ceiling_from_text(&advisory.summary, product));
    match ceiling {
        Some(c) => !version::at_or_above(scanned, &c),
        None => true,
    }
}

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
pub fn filter_npm_by_age(results: &mut [NpmPackageAdvisories], max_age_years: Option<u32>) {
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
    fn safari_advisory_dropped_when_already_patched() {
        let summary = "The issue was addressed with improved memory handling. This issue is fixed in Safari 26.5, iOS 18.7.9 and iPadOS 18.7.9, iOS 26.5 and iPadOS 26.5, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. Processing maliciously crafted web content may lead to an unexpected process crash.";
        let advisory = Advisory {
            id: "CVE-2026-28847".into(),
            source: Source::Nvd,
            summary: summary.into(),
            severity: Some(Severity::High),
            fixed_in: None,
            aliases: vec![],
            published: Some("2026-01-01T00:00:00Z".into()),
            references: vec![],
        };
        let scanned = "26.5".to_string();
        // On macOS, running Safari 26.5: the fix is already shipped ⇒ drop.
        assert!(!is_relevant(
            &advisory,
            Some(&scanned),
            Some("Safari"),
            version::Os::Macos
        ));
        // An older Safari is genuinely affected ⇒ keep.
        let old = "18.4".to_string();
        assert!(is_relevant(
            &advisory,
            Some(&old),
            Some("Safari"),
            version::Os::Macos
        ));
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
