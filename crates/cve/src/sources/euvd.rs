//! ENISA EU Vulnerability Database adapter.
//!
//! API: <https://euvdservices.enisa.europa.eu/api/search>
//!
//! EUVD doesn't have an ecosystem-based keying scheme; `/api/search` takes
//! `vendor` / `product` / `text` filters. We query by vendor+product and
//! post-filter by version on our side (EUVD entries carry `enisaIdProduct`
//! arrays that include affected-version strings).

use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::Deserialize;

use crate::advisory::{severity_from_cvss, Advisory, Severity, Source};
use crate::{cache, version, Error};

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
    products: Vec<Product>,
}

#[derive(Debug, Deserialize)]
struct Product {
    /// Affected-version expression, e.g. `"unspecified <86.0.4240.111"`,
    /// `"prior to 73.0.3683.75"`, or `"144.0.7559.99 <144.0.7559.99"`. EUVD
    /// encodes a fix ceiling (after `<` / `prior to`) and, when meaningful, a
    /// lower bound — see [`parse_range`].
    #[serde(default)]
    product_version: Option<String>,
}

/// EUVD caps `size` at 100 regardless of what we ask for.
const PAGE_SIZE: u64 = 100;
/// Hard ceiling on pages fetched, a runaway guard. Google/Chrome is the largest
/// product at ~34 pages, so this leaves generous headroom and never truncates
/// in practice.
const MAX_PAGES: u64 = 80;
/// In-flight page requests. EUVD isn't rate-limited, but we don't want a single
/// lookup to open dozens of sockets at once.
const PAGE_CONCURRENCY: usize = 8;

/// Look up EUVD entries for `(vendor, product)` and return those whose affected
/// range covers `version`.
///
/// EUVD only returns 100 entries per page, so for large products (Chrome alone
/// has thousands) we paginate using the reported `total`. Each entry's
/// `product_version` carries a fix ceiling (and sometimes a lower bound), which
/// we parse into a range and test `version` against — Chrome advisories list
/// affected *ranges*, never the exact build, so a literal match finds nothing.
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

    // First page also tells us how many entries exist in total.
    let first = fetch_page(http, vendor, product, 0).await?;
    let pages = first.total.div_ceil(PAGE_SIZE).min(MAX_PAGES);
    let mut entries = first.items;

    if pages > 1 {
        let rest: Vec<Result<SearchResponse, Error>> = stream::iter(1..pages)
            .map(|page| fetch_page(http, vendor, product, page))
            .buffer_unordered(PAGE_CONCURRENCY)
            .collect()
            .await;
        for page in rest {
            entries.extend(page?.items);
        }
    }

    let advisories: Vec<Advisory> = entries
        .into_iter()
        .filter(|entry| affects(entry, version))
        .map(to_advisory)
        .collect();

    cache::put(&cache_key, &advisories);
    Ok(advisories)
}

/// Fetch a single page of EUVD search results.
async fn fetch_page(
    http: &Client,
    vendor: &str,
    product: &str,
    page: u64,
) -> Result<SearchResponse, Error> {
    let res = http
        .get(SEARCH_URL)
        .query(&[
            ("vendor", vendor.replace(' ', "+")),
            ("product", product.replace(' ', "+")),
            ("size", PAGE_SIZE.to_string()),
            ("page", page.to_string()),
        ])
        .send()
        .await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        return Err(crate::sources::http_error(
            format!("euvd {vendor}/{product}"),
            status,
            &text,
            180,
        ));
    }
    serde_json::from_str(&text)
        .map_err(|e| Error::BadPayload(format!("euvd {vendor}/{product}: {e}")))
}

/// The affected-version range a `product_version` expression describes.
/// `upper` is the fix version (exclusive); `lower` an inclusive floor when EUVD
/// gives a meaningful one.
#[derive(Debug, PartialEq)]
enum Affected {
    /// Everything below the fix version (`unspecified <X`, `prior to X`).
    Below(String),
    /// `[lower, upper)` — both bounds meaningful and `lower < upper`.
    Range(String, String),
    /// A single affected build with no range info.
    Exact(String),
    /// Nothing version-like — can't decide, so it matches nothing.
    Unknown,
}

/// `true` if any of the entry's products is affected at `version`.
fn affects(entry: &Entry, version: &str) -> bool {
    entry.products.iter().any(|p| {
        p.product_version
            .as_deref()
            .map(parse_range)
            .is_some_and(|r| range_contains(&r, version))
    })
}

fn range_contains(affected: &Affected, version: &str) -> bool {
    use std::cmp::Ordering::{Equal, Less};
    match affected {
        Affected::Below(upper) => version::cmp(version, upper) == Less,
        Affected::Range(lower, upper) => {
            version::cmp(version, lower) != Less && version::cmp(version, upper) == Less
        }
        Affected::Exact(v) => version::cmp(version, v) == Equal,
        Affected::Unknown => false,
    }
}

/// Parse an EUVD `product_version` expression into an [`Affected`] range.
fn parse_range(raw: &str) -> Affected {
    let s = raw.trim();

    // "<X" forms: an optional lower bound, then the fix version after '<'.
    if let Some(idx) = s.find('<') {
        let upper = version_token(s[idx + 1..].trim());
        let lower = version_token(s[..idx].trim());
        return match (lower, upper) {
            // A lower bound only counts when it's a real floor below the fix.
            (Some(lo), Some(up)) if version::cmp(&lo, &up) == std::cmp::Ordering::Less => {
                Affected::Range(lo, up)
            }
            (_, Some(up)) => Affected::Below(up),
            (Some(lo), None) => Affected::Exact(lo),
            (None, None) => Affected::Unknown,
        };
    }

    // Prose ceilings: "prior to X", "before X".
    let lower = s.to_ascii_lowercase();
    for phrase in ["prior to ", "before ", "earlier than "] {
        if let Some(i) = lower.find(phrase) {
            if let Some(up) = version_token(s[i + phrase.len()..].trim()) {
                return Affected::Below(up);
            }
        }
    }

    // A bare version is a single affected build.
    match version_token(s) {
        Some(v) => Affected::Exact(v),
        None => Affected::Unknown,
    }
}

/// Extract a leading dotted-numeric version (`138.0.7204.251`) from the start of
/// `s`, or `None` for non-version tokens like `"unspecified"`. Requires at least
/// two components so a bare number isn't mistaken for a version.
fn version_token(s: &str) -> Option<String> {
    let token: String = s
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let trimmed = token.trim_matches('.');
    let components = trimmed.split('.').filter(|p| !p.is_empty()).count();
    (components >= 2 && trimmed.chars().any(|c| c.is_ascii_digit())).then(|| trimmed.to_string())
}

/// The tightest fix ceiling across an entry's products, for [`Advisory::fixed_in`].
fn entry_ceiling(entry: &Entry) -> Option<String> {
    entry
        .products
        .iter()
        .filter_map(|p| match parse_range(p.product_version.as_deref()?) {
            Affected::Below(up) | Affected::Range(_, up) => Some(up),
            Affected::Exact(_) | Affected::Unknown => None,
        })
        .min_by(|a, b| version::cmp(a, b))
}

fn to_advisory(entry: Entry) -> Advisory {
    let fixed_in = entry_ceiling(&entry);
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
        fixed_in, // parsed from the product_version fix ceiling
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

#[cfg(test)]
mod tests {
    use super::*;

    fn product(v: &str) -> Entry {
        Entry {
            id: "EUVD-TEST".into(),
            description: None,
            date_published: None,
            base_score: None,
            _base_score_version: None,
            _base_score_vector: None,
            aliases: None,
            references: None,
            products: vec![Product {
                product_version: Some(v.into()),
            }],
        }
    }

    #[test]
    fn parses_the_euvd_version_shapes() {
        assert_eq!(
            parse_range("unspecified <86.0.4240.111"),
            Affected::Below("86.0.4240.111".into())
        );
        assert_eq!(
            parse_range("prior to 73.0.3683.75"),
            Affected::Below("73.0.3683.75".into())
        );
        // Degenerate "X <X" (lower not below upper) collapses to Below(X).
        assert_eq!(
            parse_range("146.0.7680.153 <146.0.7680.153"),
            Affected::Below("146.0.7680.153".into())
        );
        // A genuine range keeps both bounds.
        assert_eq!(
            parse_range("100.0.0.0 <120.0.0.0"),
            Affected::Range("100.0.0.0".into(), "120.0.0.0".into())
        );
        assert_eq!(parse_range("garbage"), Affected::Unknown);
    }

    #[test]
    fn affects_uses_the_fix_ceiling() {
        // Discord's Chromium build is below a 142.x fix → affected.
        assert!(affects(
            &product("unspecified <142.0.7444.0"),
            "138.0.7204.251"
        ));
        // 1Password's build is at/above the fix → not affected.
        assert!(!affects(
            &product("unspecified <142.0.7444.0"),
            "142.0.7444.265"
        ));
        // Numeric, not lexicographic: 138 < 99-suffixed build comparisons.
        assert!(affects(
            &product("146.0.7680.153 <146.0.7680.153"),
            "146.0.7680.99"
        ));
        assert!(!affects(
            &product("146.0.7680.153 <146.0.7680.153"),
            "146.0.7680.153"
        ));
    }

    #[test]
    fn ceiling_is_the_tightest_fix() {
        let e = Entry {
            products: vec![
                Product {
                    product_version: Some("unspecified <120.0.0.0".into()),
                },
                Product {
                    product_version: Some("unspecified <100.0.0.0".into()),
                },
            ],
            ..product("")
        };
        assert_eq!(entry_ceiling(&e), Some("100.0.0.0".into()));
    }
}
