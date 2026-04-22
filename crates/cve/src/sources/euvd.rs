//! ENISA EU Vulnerability Database adapter.
//!
//! API: <https://euvdservices.enisa.europa.eu/api/search>
//!
//! EUVD doesn't have an ecosystem-based keying scheme; `/api/search` takes
//! `vendor` / `product` / `text` filters. We query by vendor+product and
//! post-filter by version on our side (EUVD entries carry `enisaIdProduct`
//! arrays that include affected-version strings).

use reqwest::Client;
use serde::Deserialize;

use crate::advisory::{severity_from_cvss, Advisory, Severity, Source};
use crate::{cache, Error};

const SEARCH_URL: &str = "https://euvdservices.enisa.europa.eu/api/search";

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    items: Vec<Entry>,
    #[serde(default)]
    total: u64,
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "datePublished")]
    date_published: Option<String>,
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(default, rename = "baseScoreVersion")]
    _base_score_version: Option<String>,
    #[serde(default, rename = "baseScoreVector")]
    _base_score_vector: Option<String>,
    /// Comma-joined CVE-IDs in practice — EUVD formats this as a string
    /// rather than an array.
    #[serde(default)]
    aliases: Option<String>,
    #[serde(default)]
    references: Option<String>,
    #[serde(default, rename = "enisaIdProduct")]
    products: Option<serde_json::Value>,
}

/// Look up EUVD entries for `(vendor, product)` and return any whose
/// product entries mention `version`. Best-effort: EUVD's product structure
/// is free-form, so we fall back to substring match on the serialised JSON
/// of the `enisaIdProduct` array.
pub async fn lookup(
    http: &Client,
    vendor: &str,
    product: &str,
    version: &str,
) -> Result<Vec<Advisory>, Error> {
    let cache_key = format!("euvd-{vendor}-{product}-{version}");
    if let Some(cached) = cache::get::<Vec<Advisory>>(&cache_key) {
        return Ok(cached);
    }

    let res = http
        .get(SEARCH_URL)
        .query(&[
            ("vendor", vendor.replace(' ', "+")),
            ("product", product.replace(' ', "+")),
            ("size", "100".to_string()),
            ("page", "0".to_string()),
        ])
        .send()
        .await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(Error::BadPayload(format!(
            "euvd {vendor}/{product} {status}: {}",
            truncate(&text, 180)
        )));
    }
    let parsed: SearchResponse = serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("euvd {vendor}/{product}: {e}")))?;

    let _ = parsed.total; // present for future pagination; we read 100 at a time

    let advisories: Vec<Advisory> = parsed
        .items
        .into_iter()
        .filter(|entry| mentions_version(entry, version))
        .map(to_advisory)
        .collect();

    cache::put(&cache_key, &advisories);
    Ok(advisories)
}

fn mentions_version(entry: &Entry, version: &str) -> bool {
    // EUVD product data shape isn't rigorously standardised — search the
    // serialised JSON string for a literal version match. This is coarse
    // but avoids filtering out relevant entries because of field-name drift.
    match entry.products.as_ref() {
        Some(v) => serde_json::to_string(v)
            .map(|s| s.contains(version))
            .unwrap_or(false),
        None => false,
    }
}

fn to_advisory(entry: Entry) -> Advisory {
    let aliases: Vec<String> = entry
        .aliases
        .as_deref()
        .unwrap_or("")
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    let references: Vec<String> = entry
        .references
        .as_deref()
        .unwrap_or("")
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && (s.starts_with("http://") || s.starts_with("https://")))
        .map(str::to_owned)
        .collect();

    // Pick the earliest CVE alias as the primary id if one is present —
    // that's more useful for cross-referencing than `EUVD-…`.
    let id = aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| entry.id.clone());

    Advisory {
        id,
        source: Source::Euvd,
        summary: entry.description.unwrap_or_default(),
        severity: entry.base_score.and_then(severity_from_cvss),
        fixed_in: None, // EUVD doesn't expose a clean "fixed in" version
        aliases: if aliases.is_empty() {
            vec![entry.id]
        } else {
            aliases
        },
        published: entry.date_published,
        references,
    }
}

/// Expose the Severity import at crate level to avoid the unused-import
/// warning in the small `match` expression above; the compiler can see it
/// here.
#[allow(dead_code)]
fn _severity_ref(_: Severity) {}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        format!("{}…", &s[..n])
    }
}
