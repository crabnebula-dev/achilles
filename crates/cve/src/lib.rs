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
//! | CEF (embedded Chrome) | NVD, `cpe:2.3:a:google:chrome:*`       |
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
    /// An upstream source was transiently unavailable (5xx / rate-limited)
    /// even after retries. Not actionable to the user, so it's kept out of the
    /// report's user-facing `errors` — see [`Error::is_transient`].
    #[error("temporarily unavailable: {0}")]
    Unavailable(String),
}

impl Error {
    /// True for upstream-availability failures that aren't actionable to the
    /// user: transient server errors, rate limits, and network blips. These are
    /// already retried, so when they still fail we drop them from the report's
    /// user-facing `errors` rather than surfacing raw 503 noise.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Unavailable(_) => true,
            // `is_connect` is native-only on reqwest; the wasm fetch backend has
            // no separate connect phase.
            #[cfg(not(target_arch = "wasm32"))]
            Error::Http(e) => e.is_timeout() || e.is_connect() || e.is_request(),
            #[cfg(target_arch = "wasm32")]
            Error::Http(e) => e.is_timeout() || e.is_request(),
            Error::BadPayload(_) => false,
        }
    }
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
    /// Chromium Embedded Framework advisories. CEF embeds Chromium, so these
    /// are Chromium CVEs (`cpe:2.3:a:google:chrome:*`) looked up by the
    /// embedded Chromium version — populated independently of [`Framework`], so
    /// an app that is *both* Tauri and CEF gets both buckets.
    pub cef: Vec<Advisory>,
    /// Per-source error messages encountered during this report. A single
    /// source failing never aborts the whole report — it just shows up here.
    /// Transient upstream-availability failures (5xx / rate limits) are kept
    /// out of here — see [`CveReport::unavailable`].
    pub errors: Vec<String>,
    /// Names of sources (e.g. `"NVD"`) that were transiently unavailable this
    /// run, deduplicated. These aren't hard errors worth the raw-payload noise,
    /// but the UI must still distinguish "looked up, found nothing" from
    /// "couldn't look up" — otherwise a rate-limited NVD looks like a clean
    /// bill of health for runtimes only it covers (e.g. Chromium).
    pub unavailable: Vec<String>,
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
    Cef,
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
            Bucket::Cef => &mut self.cef,
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
        // The browser controls the User-Agent (and reqwest's wasm `ClientBuilder`
        // has no `user_agent`), so only set it on native.
        #[cfg(not(target_arch = "wasm32"))]
        let http = Client::builder()
            .user_agent(concat!(
                "achilles/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/crabnebula-dev/achilles)"
            ))
            .build()
            .expect("reqwest client builder");
        #[cfg(target_arch = "wasm32")]
        let http = Client::builder().build().expect("reqwest client builder");
        Self { http, settings }
    }

    /// Build a full [`CveReport`] for a set of detected versions. Each
    /// enabled source runs independently — a single failure goes into
    /// `errors` and the report still returns. Sources disabled in settings
    /// are skipped silently.
    pub async fn report_for(&self, versions: &Versions) -> CveReport {
        self.report_for_streaming(versions, |_| {}).await
    }

    /// Like [`report_for`], but invokes `emit` with a progressively-complete
    /// snapshot of the report each time a source finishes — so the UI can
    /// paint EUVD/OSV results without waiting on a slow source (e.g. NVD
    /// retrying 503s). Each snapshot is filtered exactly like the final report,
    /// so callers can render it directly and simply replace the previous one.
    /// The returned value is the final, fully-populated report.
    pub async fn report_for_streaming<F>(&self, versions: &Versions, mut emit: F) -> CveReport
    where
        F: FnMut(CveReport),
    {
        // wasm futures (reqwest's fetch `Response`) aren't `Send`, so box them
        // without the `Send` bound there; native keeps `Send` for the
        // multi-threaded tokio runtime.
        #[cfg(not(target_arch = "wasm32"))]
        use futures::future::BoxFuture;
        #[cfg(target_arch = "wasm32")]
        use futures::future::LocalBoxFuture as BoxFuture;
        use futures::stream::{FuturesUnordered, StreamExt};

        let mut report = CveReport::default();
        let s = &self.settings.sources;
        let http = &self.http;
        // Embedded Chromium build a CEF app should be matched against. Hoisted
        // to the function scope so the lookup futures can borrow it for the
        // lifetime of the concurrent run, like the other version references.
        let cef_chromium = versions.cef.as_deref().and_then(cef_chromium_version);

        // One lookup future per (runtime, source). They're independent network
        // calls, so we run them all concurrently rather than awaiting each in
        // turn — a multi-runtime Electron app would otherwise pay for a dozen
        // serialised round-trips (with NVD rate-limited on top). We drain them
        // in completion order (not submission order) so fast sources surface
        // their results to `emit` immediately.
        #[allow(clippy::type_complexity)]
        let mut tasks: Vec<
            BoxFuture<'_, (Bucket, &'static str, String, Result<Vec<Advisory>, Error>)>,
        > = Vec::new();

        macro_rules! task {
            ($bucket:expr, $src:literal, $name:literal, $v:expr, $fut:expr) => {{
                let prefix = format!("[{}] {} {}", $src, $name, $v);
                tasks.push(Box::pin(async move { ($bucket, $src, prefix, $fut.await) }));
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

        // CEF embeds Chromium; its CVEs are Chromium's. The CEF version string
        // carries the embedded Chromium build (e.g. `…+chromium-130.0.6723.117`),
        // so we look that up against `google:chrome` just like a Chromium runtime.
        if let Some(chromium) = &cef_chromium {
            if s.nvd.enabled {
                task!(
                    Bucket::Cef,
                    "nvd",
                    "cef",
                    chromium,
                    sources::nvd::lookup_cpe_with_key(
                        http,
                        "google",
                        "chrome",
                        chromium,
                        s.nvd.api_key.as_deref()
                    )
                );
            }
            if s.euvd.enabled {
                task!(
                    Bucket::Cef,
                    "euvd",
                    "cef",
                    chromium,
                    sources::euvd::lookup(http, "Google", "Chrome", chromium)
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

        let max_age = self.settings.filters.max_age_years;
        let finalize = |raw: &CveReport| {
            let mut snapshot = raw.clone();
            apply_relevance_filter(&mut snapshot, versions);
            apply_age_filter(&mut snapshot, max_age);
            snapshot
        };

        // Sources that hit a transient failure this run, deduped and kept in a
        // stable order. We surface the source *name* (not the raw 503 payload)
        // so the UI can flag incomplete results without the noise.
        let mut unavailable: std::collections::BTreeSet<&'static str> =
            std::collections::BTreeSet::new();

        let mut pending: FuturesUnordered<_> = tasks.into_iter().collect();
        while let Some((bucket, src, prefix, result)) = pending.next().await {
            match result {
                Ok(advisories) => report.bucket_mut(bucket).extend(advisories),
                // Transient upstream failures (NVD 503s, rate limits, network
                // blips) aren't actionable and their raw bodies are noise — but
                // we still record the source name so a rate-limited NVD doesn't
                // masquerade as "no advisories" for Chromium-only runtimes.
                Err(err) if err.is_transient() => {
                    unavailable.insert(src);
                }
                Err(err) => report.errors.push(format!("{prefix}: {err}")),
            }
            report.unavailable = unavailable.iter().map(|s| s.to_uppercase()).collect();
            // Emit a filtered snapshot after every completion so the UI streams
            // results in as each source lands rather than all at once.
            emit(finalize(&report));
        }

        finalize(&report)
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
    // CEF advisories are Chromium CVEs — filter against the embedded Chromium
    // build, not the raw CEF version string.
    let cef_chromium = versions.cef.as_deref().and_then(cef_chromium_version);
    filter(&mut report.cef, cef_chromium.as_ref(), None);
}

/// Extract the embedded Chromium version from a CEF version string.
///
/// macOS CEF versions look like `130.1.18+g5e85b92+chromium-130.0.6723.117`
/// (the trailing `chromium-…` is the embedded Chromium build); the Windows /
/// Linux probe already yields a bare Chromium version. Returns `None` for
/// `"unknown"` or anything without a usable dotted-numeric version.
fn cef_chromium_version(cef: &str) -> Option<String> {
    let candidate = match cef.split_once("chromium-") {
        Some((_, rest)) => rest
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .next()
            .unwrap_or(""),
        None => cef.trim(),
    };
    let numeric = candidate.split('.').count() >= 2
        && candidate
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    numeric.then(|| candidate.to_string())
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
    filter(&mut report.cef);
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

/// Seconds since the Unix epoch. Native reads the system clock; wasm uses the
/// browser's `Date.now()`, since `std::time::SystemTime::now()` panics on
/// `wasm32-unknown-unknown`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_unix() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Current Gregorian year. Hand-rolled to avoid pulling in `chrono`.
fn current_year() -> Option<u32> {
    let secs = now_unix();
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

    #[test]
    fn cef_chromium_version_extracts_embedded_build() {
        // macOS: full CEF version with the embedded Chromium build suffix.
        assert_eq!(
            cef_chromium_version("130.1.18+g5e85b92+chromium-130.0.6723.117"),
            Some("130.0.6723.117".into())
        );
        // Windows / Linux: probe already yields a bare Chromium version.
        assert_eq!(
            cef_chromium_version("130.0.6723.117"),
            Some("130.0.6723.117".into())
        );
        // Unknown / unusable strings produce no lookup version.
        assert_eq!(cef_chromium_version("unknown"), None);
        assert_eq!(cef_chromium_version(""), None);
    }

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
