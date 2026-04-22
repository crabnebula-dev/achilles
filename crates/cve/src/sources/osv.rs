//! OSV adapter: single-package query + npm-dependency batch query.

use reqwest::Client;
use serde::Deserialize;

use crate::advisory::{Advisory, Severity, Source};
use crate::{cache, Error, NpmPackage, NpmPackageAdvisories};

const QUERY_URL: &str = "https://api.osv.dev/v1/query";
const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// OSV's `v1/querybatch` accepts up to 1000 queries per request.
const BATCH_SIZE: usize = 1000;

// ---------- OSV response schema ------------------------------------------

#[derive(Debug, Deserialize)]
struct QueryResponse {
    #[serde(default)]
    vulns: Vec<Vulnerability>,
}

/// Batch response: a list of `{ vulns: [{id}, ...] }` objects in query order.
/// Each inner vuln only contains the `id`; full detail requires a follow-up
/// lookup. For our purposes the id + subsequent `vulns/{id}` GET is enough.
#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Debug, Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVulnRef>,
}

#[derive(Debug, Deserialize)]
struct BatchVulnRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    database_specific: DatabaseSpecific,
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
}

#[derive(Debug, Deserialize)]
struct Affected {
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(default)]
    events: Vec<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

// ---------- public entry points ------------------------------------------

/// Look up `@doyensec/electronegativity`-style queries: one package, one
/// version, return every OSV vuln that covers that version.
pub async fn lookup(
    http: &Client,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<Vec<Advisory>, Error> {
    let cache_key = format!("osv-{ecosystem}-{name}-{version}");
    if let Some(cached) = cache::get::<Vec<Advisory>>(&cache_key) {
        return Ok(cached);
    }

    let body = serde_json::json!({
        "package": { "ecosystem": ecosystem, "name": name },
        "version": version,
    });
    let res = http.post(QUERY_URL).json(&body).send().await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(Error::BadPayload(format!(
            "osv {} {}: {}",
            ecosystem,
            status,
            truncate(&text, 180)
        )));
    }
    let parsed: QueryResponse = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("osv {ecosystem}: {e}")))?;
    let advisories: Vec<Advisory> = parsed
        .vulns
        .into_iter()
        .map(to_advisory)
        .collect();

    cache::put(&cache_key, &advisories);
    Ok(advisories)
}

/// Query a batch of npm packages against OSV. Returns a `NpmPackageAdvisories`
/// per input dep, preserving input order. Splits into sub-batches of
/// [`BATCH_SIZE`]. Cached per `(name, version)` — repeat scans only pay for
/// newly-seen packages.
pub async fn batch_npm(
    http: &Client,
    deps: &[NpmPackage],
) -> Result<Vec<NpmPackageAdvisories>, Error> {
    let mut out: Vec<NpmPackageAdvisories> = Vec::with_capacity(deps.len());
    let mut uncached_indices: Vec<usize> = Vec::new();

    for (i, dep) in deps.iter().enumerate() {
        let key = cache_key_for(dep);
        if let Some(cached) = cache::get::<Vec<Advisory>>(&key) {
            out.push(NpmPackageAdvisories {
                package: dep.clone(),
                advisories: cached,
            });
        } else {
            out.push(NpmPackageAdvisories {
                package: dep.clone(),
                advisories: Vec::new(),
            });
            uncached_indices.push(i);
        }
    }

    if uncached_indices.is_empty() {
        return Ok(out);
    }

    for chunk in uncached_indices.chunks(BATCH_SIZE) {
        let queries: Vec<_> = chunk
            .iter()
            .map(|&i| {
                let d = &deps[i];
                serde_json::json!({
                    "package": { "ecosystem": "npm", "name": d.name },
                    "version": d.version,
                })
            })
            .collect();

        let body = serde_json::json!({ "queries": queries });
        let res = http.post(BATCH_URL).json(&body).send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(Error::BadPayload(format!(
                "osv batch {status}: {}",
                truncate(&text, 180)
            )));
        }
        let batch: BatchResponse = serde_json::from_str(&text)
            .map_err(|e| Error::BadPayload(format!("osv batch: {e}")))?;

        // Hydrate each vuln id that fired against a dep we care about.
        for (chunk_pos, result) in batch.results.into_iter().enumerate() {
            let out_index = chunk[chunk_pos];
            let mut advisories = Vec::with_capacity(result.vulns.len());
            for vref in result.vulns {
                // Re-hydrate via GET /v1/vulns/{id} for the full record.
                match hydrate(http, &vref.id).await {
                    Ok(advisory) => advisories.push(advisory),
                    Err(_) => {
                        // Skip individual hydration failures — they shouldn't
                        // kill the batch.
                    }
                }
            }
            let key = cache_key_for(&out[out_index].package);
            cache::put(&key, &advisories);
            out[out_index].advisories = advisories;
        }
    }

    Ok(out)
}

/// Fetch the full OSV record for a specific id.
async fn hydrate(http: &Client, id: &str) -> Result<Advisory, Error> {
    let url = format!("https://api.osv.dev/v1/vulns/{id}");
    let res = http.get(&url).send().await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(Error::BadPayload(format!(
            "osv hydrate {id} {status}: {}",
            truncate(&text, 180)
        )));
    }
    let vuln: Vulnerability = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("osv hydrate {id}: {e}")))?;
    Ok(to_advisory(vuln))
}

fn to_advisory(v: Vulnerability) -> Advisory {
    use std::str::FromStr;
    let severity = v
        .database_specific
        .severity
        .as_deref()
        .and_then(|s| Severity::from_str(s).ok());
    let fixed_in = v
        .affected
        .iter()
        .flat_map(|a| a.ranges.iter())
        .flat_map(|r| r.events.iter())
        .find_map(|e| {
            e.get("fixed")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        });
    Advisory {
        id: v.id,
        source: Source::Osv,
        summary: v.summary.unwrap_or_default(),
        severity,
        fixed_in,
        aliases: v.aliases,
        published: v.published,
        references: v.references.into_iter().map(|r| r.url).collect(),
    }
}

fn cache_key_for(dep: &NpmPackage) -> String {
    format!("osv-npm-{}-{}", dep.name.replace('/', "_"), dep.version)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        format!("{}…", &s[..n])
    }
}
