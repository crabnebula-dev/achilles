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

/// Look for a `versionEndExcluding` on a matching CPE node — that's NVD's way
/// of saying "fixed in".
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
    #[serde(default, rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

// ---------- public --------------------------------------------------------

/// Query NVD for every CVE affecting `<vendor>:<product>:<version>`.
///
/// NVD's rate limit is 5 req/30s unauthenticated — we don't enforce that
/// here, we just let `reqwest` hit the endpoint and rely on the cache
/// covering 99% of repeated lookups.
pub async fn lookup_cpe(
    http: &Client,
    vendor: &str,
    product: &str,
    version: &str,
) -> Result<Vec<Advisory>, Error> {
    lookup_cpe_with_key(http, vendor, product, version, None).await
}

/// Same as [`lookup_cpe`] but sends an `apiKey` header when provided,
/// bumping the rate limit from 5 to 50 requests per 30 seconds.
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
    let mut req = http
        .get(NVD_URL)
        .query(&[("cpeName", cpe_name.as_str())])
        .timeout(Duration::from_secs(30));
    if let Some(key) = api_key {
        req = req.header("apiKey", key);
    }
    let res = req.send().await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(Error::BadPayload(format!(
            "nvd {cpe_name} {status}: {}",
            truncate(&text, 200)
        )));
    }
    let parsed: NvdResponse = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("nvd {cpe_name}: {e}")))?;

    let advisories: Vec<Advisory> = parsed
        .vulnerabilities
        .into_iter()
        .map(|wrap| to_advisory(wrap.cve, vendor, product))
        .collect();

    cache::put(&cache_key, &advisories);
    Ok(advisories)
}

fn to_advisory(cve: Cve, vendor: &str, product: &str) -> Advisory {
    use std::str::FromStr;
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

    let fixed_in = cve
        .configurations
        .iter()
        .flat_map(|c| c.nodes.iter())
        .flat_map(|n| n.cpe_match.iter())
        .find_map(|m| {
            let criteria = m.criteria.as_deref()?;
            // Match nodes specifically for our vendor/product; NVD entries
            // can reference multiple CPEs and we only care about the one
            // for the runtime we queried.
            let wanted = format!(":{vendor}:{product}:");
            if criteria.contains(&wanted) {
                m.version_end_excluding.clone()
            } else {
                None
            }
        });

    Advisory {
        id: cve.id,
        source: Source::Nvd,
        summary,
        severity,
        fixed_in,
        aliases: Vec::new(),
        published: cve.published,
        references: cve.references.into_iter().map(|r| r.url).collect(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        format!("{}…", &s[..n])
    }
}
