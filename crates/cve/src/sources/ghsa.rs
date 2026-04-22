//! GitHub Global Security Advisories adapter.
//!
//! API: <https://api.github.com/advisories>. Public advisories are readable
//! with any authenticated PAT (no scopes required). Unauthenticated access
//! exists but has a 60 req/hour limit, which is unusable for bulk scans —
//! we treat `token = None` as "skip this source."

use reqwest::Client;
use serde::Deserialize;

use crate::advisory::{Advisory, Severity, Source};
use crate::{cache, Error};
use std::str::FromStr;

const ENDPOINT: &str = "https://api.github.com/advisories";

#[derive(Debug, Deserialize)]
struct Advisory0 {
    #[serde(default)]
    ghsa_id: Option<String>,
    #[serde(default)]
    cve_id: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<Vuln>,
}

#[derive(Debug, Deserialize)]
struct Vuln {
    #[serde(default)]
    #[allow(dead_code)]
    package: Option<PackageRef>,
    #[serde(default)]
    first_patched_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PackageRef {
    #[allow(dead_code)]
    #[serde(default)]
    ecosystem: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    name: Option<String>,
}

/// Query GHSA for every advisory affecting `<ecosystem>/<name>@<version>`.
/// Returns `Ok(Vec::new())` if `token` is `None` (caller should interpret
/// that as "GHSA source disabled").
pub async fn lookup(
    http: &Client,
    token: Option<&str>,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<Vec<Advisory>, Error> {
    let Some(token) = token else {
        return Ok(Vec::new());
    };

    let cache_key = format!("ghsa-{ecosystem}-{name}-{version}");
    if let Some(cached) = cache::get::<Vec<Advisory>>(&cache_key) {
        return Ok(cached);
    }

    // `affects` accepts `name@version`; ecosystem is a separate filter.
    let affects = format!("{name}@{version}");
    let res = http
        .get(ENDPOINT)
        .query(&[
            ("ecosystem", ecosystem),
            ("affects", affects.as_str()),
            ("per_page", "100"),
        ])
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "achilles")
        .send()
        .await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(Error::BadPayload(format!(
            "ghsa {ecosystem}/{name} {status}: {}",
            truncate(&text, 200)
        )));
    }

    let parsed: Vec<Advisory0> = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("ghsa {ecosystem}/{name}: {e}")))?;

    let advisories: Vec<Advisory> = parsed.into_iter().map(to_advisory).collect();
    cache::put(&cache_key, &advisories);
    Ok(advisories)
}

fn to_advisory(a: Advisory0) -> Advisory {
    let severity = a
        .severity
        .as_deref()
        .and_then(|s| Severity::from_str(s).ok());

    let mut aliases = Vec::new();
    if let Some(cve) = a.cve_id.clone() {
        aliases.push(cve);
    }

    let id = a
        .cve_id
        .clone()
        .or_else(|| a.ghsa_id.clone())
        .unwrap_or_else(|| "GHSA-unknown".to_owned());

    let fixed_in = a
        .vulnerabilities
        .iter()
        .find_map(|v| v.first_patched_version.clone());

    let references: Vec<String> = a.html_url.into_iter().collect();

    Advisory {
        id,
        source: Source::Ghsa,
        summary: a.summary.unwrap_or_default(),
        severity,
        fixed_in,
        aliases,
        published: a.published_at,
        references,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        format!("{}…", &s[..n])
    }
}
