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
        return Err(crate::sources::http_error(
            format!("osv {ecosystem}"),
            status,
            &text,
            180,
        ));
    }
    let parsed: QueryResponse = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("osv {ecosystem}: {e}")))?;
    let advisories: Vec<Advisory> = parsed
        .vulns
        .into_iter()
        .map(|v| to_advisory(v, Some(version)))
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
            return Err(crate::sources::http_error("osv batch", status, &text, 180));
        }
        let batch: BatchResponse = serde_json::from_str(&text)
            .map_err(|e| Error::BadPayload(format!("osv batch: {e}")))?;

        // Hydrate each vuln id that fired against a dep we care about.
        for (chunk_pos, result) in batch.results.into_iter().enumerate() {
            let out_index = chunk[chunk_pos];
            let version = out[out_index].package.version.clone();
            let mut advisories = Vec::with_capacity(result.vulns.len());
            for vref in result.vulns {
                // Re-hydrate via GET /v1/vulns/{id} for the full record.
                match hydrate(http, &vref.id, Some(&version)).await {
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
///
/// `version` is the release the caller is asking about, so a multi-range
/// advisory can report the fix for the line that release is actually on.
async fn hydrate(http: &Client, id: &str, version: Option<&str>) -> Result<Advisory, Error> {
    let url = format!("https://api.osv.dev/v1/vulns/{id}");
    let res = http.get(&url).send().await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(crate::sources::http_error(
            format!("osv hydrate {id}"),
            status,
            &text,
            180,
        ));
    }
    let vuln: Vulnerability = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("osv hydrate {id}: {e}")))?;
    Ok(to_advisory(vuln, version))
}

/// The release that fixes `version`, out of an advisory that may describe
/// several affected ranges.
///
/// An advisory routinely covers more than one release line — `rand`'s
/// unsoundness is fixed in 0.8.6, 0.9.3 and 0.10.1 depending on which line you
/// are on. Taking the first `fixed` event in the record answers a question
/// nobody asked: for 0.7.3 it reports 0.9.3, a version that requires crossing
/// two majors, when 0.8.6 is the actual fix.
///
/// So walk the events of each range in order, tracking the interval an
/// `introduced` opens and a `fixed` closes, and return the fix belonging to
/// the interval that contains `version`. Falls back to the first `fixed` found
/// when the version is unknown or unparseable, which is what the caller used
/// to get for every case.
fn fixed_for(affected: &[Affected], version: Option<&str>) -> Option<String> {
    let parsed = version.and_then(|v| semver::Version::parse(v).ok());

    let has_ranges = affected.iter().any(|a| !a.ranges.is_empty());
    if let (Some(current), true) = (parsed, has_ranges) {
        for range in affected.iter().flat_map(|a| a.ranges.iter()) {
            let mut introduced: Option<semver::Version> = None;
            for event in &range.events {
                if let Some(at) = event.get("introduced").and_then(|v| v.as_str()) {
                    // OSV writes "0" for "affected from the beginning".
                    introduced = if at == "0" {
                        Some(semver::Version::new(0, 0, 0))
                    } else {
                        semver::Version::parse(at).ok()
                    };
                    continue;
                }
                let Some(at) = event.get("fixed").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Ok(fixed) = semver::Version::parse(at) else {
                    continue;
                };
                // `map_or` rather than `is_none_or`: this crate's MSRV is
                // 1.80 and the latter is only stable from 1.82.
                #[allow(clippy::unnecessary_map_or)]
                let opened = introduced.as_ref().map_or(true, |i| current >= *i);
                if opened && current < fixed {
                    return Some(at.to_owned());
                }
                introduced = None;
            }
        }
        // The version is known and every range was checked: it sits outside
        // all of them, so no fix here applies to it. Falling through would
        // hand back some other line's fix and invent an upgrade nobody needs.
        return None;
    }

    // No usable version, or an advisory that describes affected versions some
    // other way than ranges. The first fix in the record is the best available
    // answer, and what every caller used to get.
    affected
        .iter()
        .flat_map(|a| a.ranges.iter())
        .flat_map(|r| r.events.iter())
        .find_map(|e| e.get("fixed").and_then(|v| v.as_str()).map(str::to_owned))
}

fn to_advisory(v: Vulnerability, version: Option<&str>) -> Advisory {
    use std::str::FromStr;
    let severity = v
        .database_specific
        .severity
        .as_deref()
        .and_then(|s| Severity::from_str(s).ok());
    let fixed_in = fixed_for(&v.affected, version);
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

#[cfg(test)]
mod fixed_for_tests {
    use super::*;

    /// The real record for RUSTSEC-2026-0097 / GHSA-cq8v-f236-94qc: one
    /// unsoundness in `rand`, fixed separately on three release lines, and
    /// listed with the 0.9 line first.
    fn rand_advisory() -> Vec<Affected> {
        serde_json::from_value(serde_json::json!([{
            "ranges": [{
                "events": [
                    {"introduced": "0.9.0"}, {"fixed": "0.9.3"},
                    {"introduced": "0.10.0"}, {"fixed": "0.10.1"},
                    {"introduced": "0.7.0"}, {"fixed": "0.8.6"}
                ]
            }]
        }]))
        .expect("fixture parses")
    }

    #[test]
    fn the_fix_belongs_to_the_line_the_version_is_on() {
        let affected = rand_advisory();
        // 0.7.3 is fixed by 0.8.6 — not by 0.9.3, which is listed first and is
        // two majors away.
        assert_eq!(
            fixed_for(&affected, Some("0.7.3")).as_deref(),
            Some("0.8.6")
        );
        assert_eq!(
            fixed_for(&affected, Some("0.9.1")).as_deref(),
            Some("0.9.3")
        );
        assert_eq!(
            fixed_for(&affected, Some("0.10.0")).as_deref(),
            Some("0.10.1")
        );
    }

    #[test]
    fn a_version_past_every_fix_matches_no_range() {
        // 0.8.7 is past 0.8.6 and below 0.9.0: not affected at all. Nothing
        // should claim it needs the 0.9 or 0.10 fix.
        let affected = rand_advisory();
        assert_eq!(fixed_for(&affected, Some("0.8.7")), None);
    }

    #[test]
    fn an_unknown_version_falls_back_to_the_first_fix() {
        // The batch path cannot always name a version; the old behaviour is
        // still the best available answer there.
        let affected = rand_advisory();
        assert_eq!(fixed_for(&affected, None).as_deref(), Some("0.9.3"));
        assert_eq!(
            fixed_for(&affected, Some("not-a-version")).as_deref(),
            Some("0.9.3")
        );
    }

    #[test]
    fn introduced_zero_means_from_the_beginning() {
        let affected: Vec<Affected> = serde_json::from_value(serde_json::json!([{
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
        }]))
        .expect("fixture parses");
        assert_eq!(
            fixed_for(&affected, Some("0.0.1")).as_deref(),
            Some("1.2.3")
        );
    }
}
