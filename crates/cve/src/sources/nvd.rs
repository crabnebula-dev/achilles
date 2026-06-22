//! NVD REST API adapter, keyed by CPE.
//!
//! Used for runtimes that OSV doesn't cover as an ecosystem: Node.js core
//! (`cpe:2.3:a:nodejs:node.js:<ver>`) and Chromium
//! (`cpe:2.3:a:google:chrome:<ver>`).
//!
//! Rate limits: 5 requests per 30 seconds without an API key. The disk
//! cache ([`crate::cache`]) turns most repeat queries into cache hits.

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::advisory::{severity_from_cvss, Advisory, Severity, Source};
use crate::{cache, Error};

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// ---------- NVD response schema (v2.0, trimmed to what we need) -----------

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<VulnerabilityWrap>,
}

#[derive(Debug, Deserialize)]
struct VulnerabilityWrap {
    cve: Cve,
}

#[derive(Debug, Deserialize)]
struct Cve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    references: Vec<NvdReference>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

#[derive(Debug, Default, Deserialize)]
struct Metrics {
    #[serde(default, rename = "cvssMetricV31")]
    cvss_v31: Vec<CvssMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    cvss_v30: Vec<CvssMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    cvss_v2: Vec<CvssMetric>,
}

#[derive(Debug, Deserialize)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
}

/// A CPE applicability node. The version boundaries (`versionStart*` /
/// `versionEnd*`) describe the affected range; `versionEndExcluding` is also
/// NVD's way of saying "fixed in".
#[derive(Debug, Deserialize)]
struct Configuration {
    #[serde(default)]
    nodes: Vec<ConfigNode>,
}

#[derive(Debug, Deserialize)]
struct ConfigNode {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize)]
struct CpeMatch {
    #[serde(default)]
    criteria: Option<String>,
    /// Whether this match marks the product as vulnerable (vs. merely a
    /// platform/running-on constraint). NVD always sends this.
    #[serde(default)]
    vulnerable: bool,
    #[serde(default, rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(default, rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

// ---------- public --------------------------------------------------------

/// Query NVD for every CVE affecting `<vendor>:<product>:<version>`, sending an
/// `apiKey` header when provided.
///
/// NVD's rate limit is 5 req/30s unauthenticated (50 with a key) — we don't
/// enforce that here, we just let `reqwest` hit the endpoint and rely on the
/// cache covering 99% of repeated lookups.
pub async fn lookup_cpe_with_key(
    http: &Client,
    vendor: &str,
    product: &str,
    version: &str,
    api_key: Option<&str>,
) -> Result<Vec<Advisory>, Error> {
    let cache_key = format!("nvd-{vendor}-{product}-{version}");
    if let Some(cached) = cache::get::<Vec<Advisory>>(&cache_key) {
        return Ok(cached);
    }

    let cpe_name = format!("cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*");
    let text = fetch_with_retry(http, &cpe_name, api_key).await?;
    let parsed: NvdResponse = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("nvd {cpe_name}: {e}")))?;

    // NVD's `cpeName` query is not reliable at range boundaries — it can
    // return a CVE whose `versionEndExcluding` equals the queried version
    // (i.e. the version that *fixed* it). Re-check every match against the
    // affected range ourselves and drop the ones that don't actually apply.
    let advisories: Vec<Advisory> = parsed
        .vulnerabilities
        .into_iter()
        .filter_map(|wrap| to_advisory(wrap.cve, vendor, product, version))
        .collect();

    cache::put(&cache_key, &advisories);
    Ok(advisories)
}

/// Maximum number of attempts (one initial try + retries) for a single NVD
/// request.
const MAX_ATTEMPTS: u32 = 4;

/// GET the NVD endpoint for `cpe_name`, retrying transient failures.
///
/// NVD throttles aggressively when unauthenticated (5 req/30s) and tends to
/// surface that as a dropped connection or timeout ("error sending request")
/// rather than a clean 429 — so a single blip would otherwise blank out a
/// whole runtime's advisories. We retry transport errors and throttle/server
/// statuses with exponential backoff; everything else fails fast.
async fn fetch_with_retry(
    http: &Client,
    cpe_name: &str,
    api_key: Option<&str>,
) -> Result<String, Error> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut req = http
            .get(NVD_URL)
            .query(&[("cpeName", cpe_name)])
            .timeout(Duration::from_secs(30));
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }

        match req.send().await {
            Ok(res) => {
                let status = res.status();
                let text = res.text().await?;
                if status.is_success() {
                    return Ok(text);
                }
                // 429 (rate limited) and 5xx are worth another go; other
                // statuses (404, 400, …) won't change on retry.
                let retryable = status.as_u16() == 429 || status.is_server_error();
                if retryable && attempt < MAX_ATTEMPTS {
                    backoff(attempt).await;
                    continue;
                }
                return Err(crate::sources::http_error(
                    format!("nvd {cpe_name}"),
                    status,
                    &text,
                    200,
                ));
            }
            Err(e) => {
                // Transport-level failure: timeout, connection reset, refused.
                let transient = e.is_timeout() || e.is_connect() || e.is_request();
                if transient && attempt < MAX_ATTEMPTS {
                    backoff(attempt).await;
                    continue;
                }
                return Err(Error::Http(e));
            }
        }
    }
}

/// Exponential backoff sized to NVD's 30-second window: ~2s, 4s, 8s. Capped so
/// a stuck runtime can't stall a scan indefinitely.
async fn backoff(attempt: u32) {
    let secs = (1u64 << attempt).min(8); // attempt 1→2s, 2→4s, 3→8s
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// Returns `Some(advisory)` only when `version` genuinely falls inside the
/// affected range described by one of the CVE's CPE matches for our
/// vendor/product. Returns `None` when the version is at or past the fix (or
/// otherwise outside every affected range), so already-patched runtimes don't
/// get flagged.
fn to_advisory(cve: Cve, vendor: &str, product: &str, version: &str) -> Option<Advisory> {
    use std::str::FromStr;

    // CPE matches that reference the runtime we actually queried. NVD entries
    // can list multiple CPEs (e.g. an OS the product runs on); we only care
    // about our own vendor/product.
    let wanted = format!(":{vendor}:{product}:");
    let our_matches: Vec<&CpeMatch> = cve
        .configurations
        .iter()
        .flat_map(|c| c.nodes.iter())
        .flat_map(|n| n.cpe_match.iter())
        .filter(|m| m.criteria.as_deref().is_some_and(|c| c.contains(&wanted)))
        .collect();

    // The queried version is affected only if at least one vulnerable match
    // for our product actually covers it.
    let affected = our_matches
        .iter()
        .any(|m| m.vulnerable && match_covers_version(m, version));
    if !affected {
        return None;
    }

    let summary = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let cvss = cve
        .metrics
        .cvss_v31
        .first()
        .or_else(|| cve.metrics.cvss_v30.first())
        .or_else(|| cve.metrics.cvss_v2.first());

    let severity = cvss
        .and_then(|m| m.cvss_data.base_severity.as_deref())
        .and_then(|s| Severity::from_str(s).ok())
        .or_else(|| {
            cvss.and_then(|m| m.cvss_data.base_score)
                .and_then(severity_from_cvss)
        });

    // Report the fix from the range that applies to our version.
    let fixed_in = our_matches
        .iter()
        .find(|m| m.vulnerable && match_covers_version(m, version))
        .and_then(|m| m.version_end_excluding.clone());

    Some(Advisory {
        id: cve.id,
        source: Source::Nvd,
        summary,
        severity,
        fixed_in,
        aliases: Vec::new(),
        published: cve.published,
        references: cve.references.into_iter().map(|r| r.url).collect(),
    })
}

/// Does this CPE match cover `version`?
///
/// Two shapes appear in NVD data:
///   * a wildcard criteria (`…:chrome:*:…`) constrained by `versionStart*` /
///     `versionEnd*` boundaries — check the boundaries.
///   * an explicit version pinned in the criteria (`…:chrome:148.0.7778.1:…`)
///     with no boundaries — the queried version must equal it.
fn match_covers_version(m: &CpeMatch, version: &str) -> bool {
    let has_bounds = m.version_start_including.is_some()
        || m.version_start_excluding.is_some()
        || m.version_end_including.is_some()
        || m.version_end_excluding.is_some();

    if !has_bounds {
        // No range: fall back to the version embedded in the CPE criteria.
        // `*` / `-` mean "any version" — conservatively treat as covered.
        return match m.criteria.as_deref().and_then(cpe_version) {
            Some(v) if v != "*" && v != "-" => crate::version::cmp(version, v).is_eq(),
            _ => true,
        };
    }

    use crate::version::cmp;
    use std::cmp::Ordering::{Equal, Greater, Less};
    if let Some(s) = &m.version_start_including {
        if cmp(version, s) == Less {
            return false;
        }
    }
    if let Some(s) = &m.version_start_excluding {
        if matches!(cmp(version, s), Less | Equal) {
            return false;
        }
    }
    if let Some(e) = &m.version_end_including {
        if cmp(version, e) == Greater {
            return false;
        }
    }
    if let Some(e) = &m.version_end_excluding {
        if matches!(cmp(version, e), Greater | Equal) {
            return false;
        }
    }
    true
}

/// Extract the version field (index 5) from a CPE 2.3 string:
/// `cpe:2.3:<part>:<vendor>:<product>:<version>:…`.
fn cpe_version(criteria: &str) -> Option<&str> {
    criteria.split(':').nth(5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn end_excluding(fixed: &str) -> CpeMatch {
        CpeMatch {
            criteria: Some("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*".into()),
            vulnerable: true,
            version_start_including: None,
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some(fixed.into()),
        }
    }

    #[test]
    fn fixed_version_is_not_flagged() {
        // The reported bug: running version == versionEndExcluding (the fix).
        let m = end_excluding("148.0.7778.216");
        assert!(
            !match_covers_version(&m, "148.0.7778.216"),
            "the version that fixed the CVE must not be reported as affected"
        );
    }

    #[test]
    fn version_below_fix_is_flagged() {
        let m = end_excluding("148.0.7778.216");
        assert!(match_covers_version(&m, "148.0.7778.215"));
    }

    #[test]
    fn version_above_fix_is_not_flagged() {
        let m = end_excluding("148.0.7778.216");
        assert!(!match_covers_version(&m, "149.0.0.0"));
    }

    #[test]
    fn respects_lower_bound() {
        let mut m = end_excluding("148.0.7778.216");
        m.version_start_including = Some("148.0.7000.0".into());
        assert!(match_covers_version(&m, "148.0.7500.0"));
        assert!(!match_covers_version(&m, "147.0.0.0"));
    }

    #[test]
    fn pinned_version_requires_exact_match() {
        let m = CpeMatch {
            criteria: Some("cpe:2.3:a:google:chrome:148.0.7778.215:*:*:*:*:*:*:*".into()),
            vulnerable: true,
            version_start_including: None,
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: None,
        };
        assert!(match_covers_version(&m, "148.0.7778.215"));
        assert!(!match_covers_version(&m, "148.0.7778.216"));
    }

    #[test]
    fn cpe_version_extracts_field_5() {
        assert_eq!(
            cpe_version("cpe:2.3:a:google:chrome:148.0.7778.215:*:*:*:*:*:*:*"),
            Some("148.0.7778.215")
        );
        assert_eq!(
            cpe_version("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"),
            Some("*")
        );
    }
}
